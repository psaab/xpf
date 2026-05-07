---
status: REVISED v6 — addresses Codex round-5 PLAN-NEEDS-MINOR (task-movpjn74): 2 final stale-residue fixes ('200 LOC' at line 101 → '~250 LOC'; 'v3 added the tempfile crate' at line 30 → 'v3 proposed adding...'). Gemini round-2 PLAN-READY (task-movpbwzi); Codex round-6 verify pending. Implementation begins in parallel — text-only cleanup does not block code work.
issue: #547
phase: implementation plan
prerequisites:
  - PR #1217 (fairness-regimes contract) MERGED as e1ec6b90 ✓
  - PR #1220 (fairness harness) MERGED as bf87cf71 ✓
---

## v4 — Codex round-3 + Gemini round-1-retry findings addressed

**Codex round-3 (task-movp0i14, PLAN-NEEDS-MINOR)** — 2 stale-residue
findings:

1. §5 "Hidden invariants" contradicted v3 §3.5 "Black-box discipline".
   The former said "the fixture computes expected values via direct
   call to `compute_cstruct`"; the latter explicitly forbade that.
   v4 fix: §5 reworded to clarify `compute_cstruct` is the single
   source of truth *internally* (called by `fairness-eval` itself),
   and the integration test does NOT import it.

2. Stale v2 residue: "5 cases", "~150-200 LOC", old open questions
   referencing the now-wrong empty-TSV-Gate-2 claim. v4 fix: cleaned
   up to "6 cases", "~250 LOC", and consolidated open questions
   into a "resolved by review rounds" structure.

**Gemini round-1-retry (task-movp199v, PLAN-NEEDS-MINOR)** — one
finding:

3. v3 proposed adding the `tempfile` crate as a dev-dep. Gemini pointed out
   that `fairness-eval.rs::tsv_tests::write_tmp` (line 729+ at HEAD,
   commit 9d3faf02) already uses
   `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()` +
   `process::id()` for collision-resistant tempfile naming. v4 fix:
   reuse that pattern via a 10-line `TempGuard` struct with `Drop`
   impl. No new dev-dep; workspace dependency tree unchanged.

Both reviewers also flagged a strategic note: with #1211 closed and
Path 4 not yet captured as an issue, the fixture's value is
"fairness-eval CLI/IO regression coverage" (defensible) but not
architecturally exciting. v4 keeps the implement-now path because
the user's standing mandate is to drive per-5-tuple fairness; the
harness binary is already the merge bar for any future fairness PR;
locking down its contract is standalone-valuable. The PLAN-KILL
escape hatch is preserved if circumstances change.

## v3 — Codex round-2 findings addressed

Codex round-2 (task-movoly14) PLAN-NEEDS-MINOR. v2 fixed the round-1
architectural problems but five cleanup items remained:

1. **Black-box boundary still violated.** v2 said the fixture would
   compute expected Cstruct via direct call to `compute_cstruct`,
   citing `#[cfg(test)] mod fairness;` in `main.rs`. That module is
   not available to an integration test in `userspace-dp/tests/`
   because `userspace-dp` has bin targets, not a lib target.
   Re-adding `#[path = "../src/fairness.rs"] mod fairness;` would
   compile but reintroduces the internal math coupling v2 was
   trying to remove. **v3 fix**: assert subprocess-visible contract
   only — exit code, verdict string, failure_reasons class
   membership, required JSON keys, distribution_a_i values from the
   TSV, broad numeric relationships like `gap <= epsilon` /
   `gap > epsilon`. **No** equality check against an internally-
   computed Cstruct.

2. **Required-key set was inconsistent.** PASS case asserted
   `n_active`, but `n_active` was not in the required-keys set.
   **v3 fix**: required keys are {distribution_a_i, n_active,
   cstruct, observed_cov, gap, saturated, a_i_sum_check_ok,
   starved_flow_count, verdict, failure_reasons} = **10 keys**.
   `saturated` stays because the contract calls it operator-visible
   (`docs/fairness-regimes.md:240`). The remaining 6 fields
   (n_total_workers, epsilon, aggregate_mbps, a_i_sum,
   iperf_non_starved_streams, a_i_sum_tolerance) are diagnostic.

3. **Test command was wrong.** v2 said `cargo test --release`, but
   the repo has no root Cargo.toml. **v3 fix**: documented as
   `cargo test --manifest-path userspace-dp/Cargo.toml --release`
   for the full suite and `cargo test --manifest-path
   userspace-dp/Cargo.toml --release --test fairness_eval_blackbox`
   for the focused integration test.

4. **Empty-input semantics were wrong.** v2 said empty TSV would
   be Gate 2 FAIL. Codex pointed out: with equal iperf streams,
   `observed_cov == 0` and `cstruct == 0`, so it's actually the
   **sum guard** that fires (Guard FAIL). Empty intervals are
   worse — current code can emit PASS if `test_start.duration` is
   long enough and the sum guard happens to hold. **v3 fix**:
   empty-TSV case is added to the Guard FAIL branch, not Gate 2.
   Empty-intervals case is **not** added; that would require a
   production-code fix and is out of scope.

5. **Tempfile naming was fragile.** v2 used PID-based naming, which
   is not collision-proof under cargo's parallel test runner. **v3
   proposed**: add `tempfile` crate as dev-dep in
   `userspace-dp/Cargo.toml`; use `tempfile::tempdir()`.
   **v4 superseded that** with the hand-rolled `TempGuard`
   approach (see §3.3 below) — the tempfile dep is NOT actually
   added.

Codex round-2's cost/benefit verdict was clear: **the ~600 LOC
(test code + helper functions + comments) is worth it** if
`fairness-eval` remains a supported harness binary.
The shell harness `test/incus/fairness-harness.sh:98` shells out and
relies on exit codes + stdout JSON, and unit tests do NOT cover that
boundary. v3 keeps that scope.

## v2 — Codex round-1 findings addressed

Codex round-1 (task-movo6xm1) PLAN-NEEDS-MAJOR. v1's framing was
wrong in three substantive ways:

1. **Fixture matrix duplicated `fairness.rs::tests` + `fairness-eval`
   bin tests.** The 5 worked-example distributions are already pinned
   in those test modules. Re-pinning them via subprocess is slower
   duplication, not new coverage. v2 reframes the fixture around
   **black-box binary contract coverage**: CLI args, file IO, exit
   codes, stdout JSON shape, and the interaction between iperf JSON
   plus binding TSV — none of which the unit tests exercise.

2. **The "saturation negative" was architecturally wrong.**
   `fairness-eval` computes `saturated: bool` as a diagnostic, but
   `failure_reasons` only includes starved-flow / Gate 2 / sum-guard.
   A "saturation negative" cannot assert `verdict == FAIL`. v2 drops
   the saturation negative from the verdict-asserting test set. It
   may live as a *diagnostic-classification* test (assert that
   `saturated == true` for an oversubscribed input) but does not gate
   PASS/FAIL.

3. **Subprocess path was fragile.** v1 used
   `Command::new("./target/release/fairness-eval")` which depends on
   the current working directory and pre-built target. v2 uses
   Cargo's `env!("CARGO_BIN_EXE_fairness-eval")` which is set by
   cargo when running an integration test that has the bin as an
   automatic dependency. No feature-gate; runs in default
   `cargo test --release`.

Codex also flagged the v1 value claim ("future fairness-mechanism
PRs can cite this fixture as the merge bar") as overstated. v2
narrows the value: the fixture validates `fairness-eval`'s
CLI/IO/exit-code contract for synthetic inputs. It does **not**
validate any future fairness mechanism — it has no flow_cache, no
RSS, no packets. Mechanism validation belongs at the cluster harness
level.

## 1. Issue framing

`#547 — Deterministic RSS-skew test fixture`. The harness shipped in
PR #1220 (`fairness-eval` binary + `test/incus/fairness-harness.sh`)
runs end-to-end on the loss userspace cluster. The pure-fns inside
it (`compute_cstruct`, `compute_observed_cov`, `starved_flow_count`,
`is_saturated`) plus the per-worker aggregation helper
(`aggregate_per_worker`, `direction_multiplier`) and the TSV parser
(`parse_binding_flows_tsv`) are unit-tested at HEAD. What is **not**
tested at HEAD is the binary's external contract: argument parsing,
file IO, exit codes, and the shape of the verdict JSON written to
stdout.

A regression in *any* of those would silently corrupt the cluster
harness's output. cargo's unit tests on the pure-fns would still pass
because they don't call `main()`. The risk surface is small but
real.

#547 fills that gap with 6 black-box integration test cases plus 1
required-keys schema test (7 tests total) that invoke `fairness-eval`
as a subprocess, feed it synthetic `iperf3.json` + `binding-flows.tsv`
files, and assert the binary contract — black-box-only, no
internal-helper coupling.

## 2. Honest scope/value framing

**What this PR delivers**: 6 cargo integration test cases plus 1
required-keys schema test (7 tests total, in
`userspace-dp/tests/fairness_eval_blackbox.rs`) that exercise
`fairness-eval`'s external contract via subprocess + stdout JSON
inspection only. **No** internal-helper imports.

1. **PASS case**: skewed but contract-clearing distribution with
   iface noise on a different iface. Asserts `distribution_a_i`,
   `n_active > 0`, `gap <= epsilon`, exit code 0,
   `verdict == "PASS"`. Numeric values like `cstruct` and
   `observed_cov` are read from the JSON but checked only against
   broad relationships (e.g. `gap = observed_cov - cstruct`,
   `cstruct >= 0`); not against an internally-computed expected
   value.
2. **Gate 1 FAIL** (starved): one persistently starved connected
   stream throughout the steady-state window. Asserts
   `failure_reasons` contains a "starved" message,
   `verdict == "FAIL"`, exit code 1.
3. **Gate 2 FAIL** (CoV gap > epsilon): no starved streams, but
   per-flow throughput skew exceeds the structural CoV ceiling by
   more than `EPSILON = 0.05`. Asserts `failure_reasons` contains a
   "Gate 2" message, `verdict == "FAIL"`, exit code 1.
4. **Guard FAIL — sum mismatch**: `sum(a_i)` differs from
   non-starved iperf streams by more than tolerance, isolated from
   Gate 1/2. Asserts `failure_reasons` contains a "Harness guard"
   message, `verdict == "FAIL"`, exit code 1.
5. **Guard FAIL — empty TSV**: TSV with header only, no rows. With
   equal iperf streams, `observed_cov == 0` and `cstruct == 0`, so
   Gate 2 doesn't fire — but the sum guard does (`sum(a_i) == 0`
   vs non-starved streams > 0). Asserts `failure_reasons` contains
   "Harness guard", verdict FAIL, exit code 1. (Codex round-2
   finding #4: this is the correct branch for empty TSV, not Gate 2.)
6. **Exit 2 case** (operational error): malformed input — out-of-range
   `worker_id` (≥ `--n-workers`). Asserts exit code 2 with the
   current `Err`-on-out-of-range behavior at HEAD. (No verdict JSON
   is emitted.)

**What it does NOT deliver** (explicitly out of scope after v2 rewrite):

- Re-pinning the same 5 distributions that `fairness.rs::tests`
  already pins. Those tests already cover the math; subprocess
  re-validation adds no value.
- A "saturation negative" that asserts `verdict == FAIL` based on
  the saturated boolean. The saturated flag is diagnostic, not in
  failure_reasons.
- A synthetic flow generator that drives BPF / userspace-dp
  flow_cache with controlled RSS distribution. Different problem,
  much larger swing.
- A claim that #547 validates future fairness mechanisms. It does
  not — it validates `fairness-eval`'s CLI/IO contract only.

**Concrete value**: a regression in `fairness-eval`'s argument
parsing, file IO, exit codes, or verdict JSON shape would be caught
locally rather than discovered when the cluster harness silently
returns garbage. The 6 cases also serve as executable documentation
for what the binary's contract IS.

If reviewers conclude that the binary contract is small enough that
this kind of regression coverage is overkill, **PLAN-KILL is an
acceptable verdict**. The fairness-eval binary is ~600 LOC; the
integration tests are ~640 LOC including helpers and schema test
(measured on the v6+ implementation).

Both round-3 reviewers explicitly noted "if Path 4 is not going to
ship, this is YAGNI; consider PLAN-KILL". The strategic call is:
the user's standing mandate is to drive per-5-tuple fairness; even
if Path 4 stalls, the harness binary is already the merge bar for
any future fairness PR, so locking down its contract has standalone
regression-coverage value. v4 keeps the implement-now path; the
PLAN-KILL escape hatch is preserved if circumstances change.

## 3. Concrete design

### 3.1 Test layout

`userspace-dp/tests/fairness_eval_blackbox.rs`. New top-level
integration test file. Cargo auto-discovers `tests/*.rs` and runs
each as its own binary; the `fairness-eval` bin is automatically
built and exposed via `env!("CARGO_BIN_EXE_fairness-eval")`.

### 3.2 Subprocess invocation

```rust
fn run_fairness_eval(
    iperf_json_path: &Path,
    tsv_path: &Path,
    args: &[&str],
) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_fairness-eval");
    Command::new(bin)
        .args([
            "--iperf-json", iperf_json_path.to_str().unwrap(),
            "--binding-flows", tsv_path.to_str().unwrap(),
        ])
        .args(args)
        .output()
        .expect("fairness-eval invocation")
}
```

### 3.3 Synthetic input synthesis

iperf3 JSON: minimum schema needed by the parser. From
`fairness-eval.rs` Iperf3Output / Iperf3Start / Iperf3TestStart /
Iperf3Connected / Iperf3Interval / Iperf3StreamInterval at HEAD
(commit bf87cf71 → 9d3faf02). Use serde_json::json! to build the
minimum: `{ "start": { "connected": [{"socket": N, "local_port":
P}, ...], "test_start": {"duration": D, "num_streams": N} },
"intervals": [...] }`.

TSV: 6-column format, header `# timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount`,
then rows synthesised from a `Vec<(u64, u32, u32, u32, &str, u32)>`
spec.

**Tempfile** (v4 fix per Gemini round-1 retry): re-use the
`SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()` +
`process::id()` pattern that `fairness-eval.rs::tsv_tests` already
uses (line 729+ at HEAD, commit 9d3faf02). Wrap it in a 10-line `struct
TempGuard(PathBuf)` with a custom `Drop` impl that recursively
removes the tempdir. No new dev-dep — keeps the workspace
dependency tree unchanged.

```rust
struct TempGuard(PathBuf);
impl TempGuard {
    fn new(prefix: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create tempdir");
        Self(p)
    }
    fn path(&self) -> &Path { &self.0 }
}
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
```

Cleanup runs even if the test panics (Drop is run during stack
unwinding), matching the `tempfile::tempdir()` guarantee.

(v3 had proposed adding the `tempfile` crate as a dev-dep; Gemini
round-1 retry pointed out this is unnecessary bloat given an
existing pattern is already in the codebase.)

### 3.4 Verdict JSON parsing — by required keys, not full schema

**Codex round-1 finding #5 (and round-2 follow-up #2)**: the Verdict
struct has 16 fields. A fixture that pattern-matches on all 16 would
silently fail any future additive change. v3 parses by required keys
only — expanded from 8 in v2 to 10 in v3 because round-2 caught that
`n_active` (asserted by the PASS case) and `starved_flow_count`
(structurally important) were missing:

```rust
#[derive(Deserialize)]
struct VerdictRequiredFields {
    distribution_a_i: Vec<u32>,
    n_active: u32,
    cstruct: f64,
    observed_cov: f64,
    gap: f64,
    saturated: bool,
    a_i_sum_check_ok: bool,
    starved_flow_count: u32,
    verdict: String,
    failure_reasons: Vec<String>,
}
```

The fixture asserts on these 10 keys. The remaining 6 fields
(n_total_workers, epsilon, aggregate_mbps, a_i_sum,
iperf_non_starved_streams, a_i_sum_tolerance) are diagnostic; future
additions/removals don't break the fixture. If a *new* gate appears
that adds a failure_reasons string class, the corresponding fixture
case will need updating — and that's the right boundary.

A separate one-line test (`verdict_emits_required_keys`) inspects
the raw JSON object to confirm all 10 required keys are present, so
a rename of any required key (which IS a contract break) fails the
fixture loudly.

### 3.5 Black-box discipline (v3 — Codex round-2 finding #1)

The fixture must NOT import `userspace_dp::fairness::*` or any other
internal-helper symbol. Specifically:

- **No** `compute_cstruct(...)` call from the test to compute an
  expected value to compare against.
- **No** `#[path = "../src/fairness.rs"] mod fairness;` shortcut.
- **No** assertion of internal-math equality (`assert_eq!(verdict.cstruct,
  fairness::compute_cstruct(&dist))`).

Instead the fixture asserts:

- **Exit code**: 0 PASS / 1 FAIL / 2 error.
- **Verdict string**: `verdict == "PASS"` or `"FAIL"`.
- **Failure-class membership**: `failure_reasons.iter().any(|r|
  r.contains("starved"))` etc.
- **Distribution from input**: the `distribution_a_i` JSON value
  matches the `{a_i}` the fixture wrote into the TSV.
- **Numeric relationships**: `gap = observed_cov - cstruct` (within
  fp tolerance), `cstruct >= 0`, `observed_cov >= 0`,
  `gap > epsilon ⇔ Gate-2 in failure_reasons`, etc.

This keeps the fixture as a true black-box harness for the binary's
contract, which is the only coverage gap unit tests don't already
fill.

## 4. Public API preservation

None. Tests-only.

## 5. Hidden invariants the change must preserve

- `fairness-eval` exit code semantics: 0 PASS, 1 FAIL, 2 IO/parse
  error. Each fixture case asserts the right exit.
- 6-column TSV parser silently skips malformed rows; the fixture
  must produce well-formed rows or its black-box assertions will
  fail through subprocess output, not through internal parser
  coupling.
- `compute_cstruct` is the single source of truth for Cstruct math
  *internally* (called by `fairness-eval` itself). v3 §3.5 forbids
  the integration test from importing it — the fixture asserts
  binary-contract values from the JSON, not against an
  internally-recomputed Cstruct.
- The legacy 3-col TSV path is NOT exercised by these tests (it's
  exercised by the existing `tsv_tests` unit module). v3 fixture
  uses 6-col only.

## 6. Risk assessment

| Risk class | Level | Note |
|---|---|---|
| Behavioral regression risk | NONE | tests-only PR; no production code touched |
| Lifetime / borrow-checker risk | LOW | hand-rolled `TempGuard` + Drop; no Arc/Mutex; no new deps |
| Performance regression risk | NONE | not on any hot path |
| Architectural mismatch risk | LOW | 6 test cases against a stable binary contract |

## 7. Test plan

- [ ] `cargo test --manifest-path userspace-dp/Cargo.toml --release`
  — all 1006+31+8 existing tests pass + 6 new integration tests + 1
  required-keys schema test (target: 7 new). v3 fix per Codex
  round-2 finding #3 (no root Cargo.toml at repo root).
- [ ] `cargo test --manifest-path userspace-dp/Cargo.toml --release
  --test fairness_eval_blackbox` — focused integration test passes
  5/5 in a row (flake check).
- [ ] `go test ./...` — unchanged; tests-only PR.
- [ ] No CoS smoke matrix needed — this PR doesn't touch dataplane.

## 8. Out of scope (explicitly)

- Synthetic packet generator that drives BPF/userspace-dp flow_cache
  with controlled RSS distribution.
- Cluster-level integration test that drives `iperf3 -P N` and then
  asserts the harness's verdict against the fixture's prediction.
- Adding the fixture as a CI gate (no GitHub-side CI on this repo).
- Re-pinning fairness.rs::tests's 5 worked examples.
- Asserting `verdict == FAIL` on a saturation-only basis.
- Validating future fairness mechanisms.

## 9. Open questions resolved by review rounds

(v1, v2, v3, v4 questions consolidated. Resolved questions removed;
new v4-only questions kept open.)

1. **Is the 6-case set complete?** PASS / Gate 1 FAIL / Gate 2 FAIL
   / Guard FAIL — sum mismatch / Guard FAIL — empty TSV / Exit 2.
   Codex round-3 confirmed this is the right enumeration for this
   PR's stated scope. Empty intervals can stay out of scope (would
   require a production-code fix to fairness-eval; not what this PR
   is about).
2. **Required-keys schema**: 10 required vs 6 diagnostic. Codex
   round-3 + Gemini round-1 retry both confirmed the split is
   correct, including `saturated` in required because it's
   operator-visible per `docs/fairness-regimes.md:240`.
3. **Subprocess vs in-process**: resolved in round-1 — subprocess
   is the right boundary because the production harness shells out
   to the binary. cargo's `CARGO_BIN_EXE_<name>` env var is auto-set
   for same-package bin targets; no dev-dep on bin needed
   (Codex round-3 + Gemini round-1 retry confirmed).
4. **Tempfile cleanup**: resolved in v4 — hand-rolled `TempGuard`
   with `Drop` impl, reusing `fairness-eval.rs::tsv_tests`'s
   `SystemTime::now().as_nanos()` + `process::id()` pattern. No new
   dep. Drop fires during stack unwinding so test-panic cleanup is
   covered.
5. **Race against concurrent test runs**: resolved by the same
   `nanos + pid` pattern in #4. nanos provides per-test-run
   uniqueness; pid provides cross-test-binary uniqueness. v4
   includes the test function name in the prefix as additional
   defense.

## 10. Methodology

- v2 plan committed; Codex round-1 MAJOR addressed; pending Gemini
  round-1 (still running at v2 commit time) plus Codex round-2
  verify.
- Iterate until both PLAN-READY (or both PLAN-KILL — acceptable
  here).
- Implement; cargo test 5x flake check; open PR; wait for Copilot.
- Triple-review the code; merge on consensus.

PLAN-KILL is still a real possibility. The fixture's value is
proportional to how much we expect future fairness-mechanism PRs to
exist. With #1211 archived (PLAN-KILL), Path 4 workload-aware gate
is the only remaining mechanism candidate, and it doesn't exist as
an issue yet. If Path 4 also PLAN-KILLs at plan time, #547's payoff
collapses to "minor regression-coverage on a stable 600-LOC binary".
That may not justify even ~640 LOC of test code.
