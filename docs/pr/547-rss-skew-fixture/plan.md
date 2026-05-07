---
status: DRAFT v1 — pending adversarial plan review (Codex hostile + Gemini adversarial)
issue: #547
phase: implementation plan
prerequisites:
  - PR #1217 (fairness-regimes contract) MERGED as e1ec6b90 ✓
  - PR #1220 (fairness harness) MERGED as bf87cf71 ✓
---

## 1. Issue framing

`#547 — Deterministic RSS-skew test fixture`. The harness shipped in
PR #1220 reads whatever per-worker active-flow distribution the
cluster's RSS hash + indirection table happens to produce on the day.
This is the *right* operational signal — it tells us what the
firewall actually saw — but for the purpose of validating the
harness itself (and gating future fairness-mechanism PRs), we need a
deterministic input: a fixture that injects a *known* per-worker
distribution `{aᵢ}` and lets us assert the harness's verdict matches
a hand-computed expected verdict.

Without this fixture:

- Every fairness-mechanism PR has to reason about whether the
  harness's PASS/FAIL verdict on a given run was a real win or just
  RSS noise.
- Regressions in the harness itself (e.g. a bug in `aggregate_per_worker`
  or `compute_cstruct`) show up only as "the verdict on the cluster
  feels wrong somehow" rather than as a deterministic test failure.
- New plan reviewers cannot bench a proposed mechanism against the
  harness with concrete numbers — only against hypotheticals.

## 2. Honest scope/value framing

**What this PR delivers**: a deterministic test that drives a known
per-worker `{aᵢ}` distribution into the harness's evaluation pipeline
and asserts the verdict matches the hand-computed expected output.

**What it does NOT deliver**: a synthetic flow generator that
produces wire-level packets to drive the BPF/userspace-dp flow_cache
with controlled RSS distribution. That's a much larger swing
(networking, SR-IOV, kernel RSS configuration) and isn't necessary
for the gate this fixture is supposed to be.

**Concrete value**: every future fairness-mechanism plan can cite
this fixture's verdict on its targeted distribution as the merge
bar. Without it, plan reviews will keep arguing from hypotheticals
about "what would the harness say on a worst-case RSS distribution".

If reviewers conclude that the fixture's value is too small to
justify the LOC, **PLAN-KILL is an acceptable verdict**. The harness
is already useful operationally; the fixture just makes it useful as
a regression gate.

## 3. Concrete design

The harness's evaluation pipeline (`fairness-eval` binary) takes two
inputs:

1. `iperf3 -J` JSON output (per-stream throughput).
2. A 6-column TSV of per-binding active-flow snapshots (timestamp,
   binding_slot, queue_id, worker_id, iface, count).

The fixture synthesises both inputs from a declarative spec:

```rust
// tests/fairness-fixture.rs (new integration test, gated by feature
// "fairness-fixture" so it's not built in the default cargo test
// path; alternative: top-level `tests/` dir Rust integration test).
struct FairnessFixture {
    /// Per-worker distribution to inject. e.g. [2,2,2,2,2,2] for
    /// balanced; [6,0,0,0,0,6] for severe two-worker skew; [4,1,1,1,1,1]
    /// for moderate single-hot skew.
    a_i: Vec<u32>,
    /// Per-stream throughput in bps for the iperf3 JSON. Length must
    /// equal sum(a_i) (one stream per active flow).
    per_stream_bps: Vec<u64>,
    /// Test duration in seconds (passes through to iperf3 JSON
    /// test_start.duration and per-interval boundaries).
    duration_s: u64,
    /// Iface name to filter on (default ge-0-0-2). Non-matching
    /// "noise" rows are also injected to verify the iface filter
    /// drops them.
    iface: String,
    /// Shaper rate in bits/sec for the saturation gate.
    shaper_rate_bps: u64,
}
```

The fixture writes synthetic `iperf3.json` and `binding-flows.tsv`
files to a tempdir, runs `fairness-eval` as a subprocess, parses the
verdict JSON, and asserts:

- `distribution_a_i == fixture.a_i`
- `n_active == count of non-zero entries in fixture.a_i`
- `cstruct == hand-computed Cstruct(fixture.a_i)` (use the same
  `compute_cstruct` from the merged `fairness.rs`)
- `observed_cov == hand-computed CoV(fixture.per_stream_bps)`
- `gap == observed_cov - cstruct`
- `verdict == expected_verdict` (PASS / FAIL based on gap > epsilon
  or starved-flow count)
- `a_i_sum_check_ok == true` (otherwise the fixture is internally
  inconsistent)

### Worked example fixtures

Pin the same 5 distributions used in `fairness.rs::tests`:

1. `{2,2,2,2,2,2}` perfectly balanced, Cstruct=0.00. Per-stream
   throughputs balanced → observed_CoV ≈ 0 → verdict PASS.
2. `{1,1,2,2,3,3}` moderate skew, Cstruct=0.47. Per-stream throughputs
   matched to the structural ceiling → verdict PASS at the boundary.
3. `{0,2,2,2,3,3}` one idle worker, Cstruct=0.20. → PASS.
4. `{1,3,0,0,0,0}` severe skew, Cstruct=0.58. → PASS at boundary.
5. `{6,0,0,0,0,6}` degenerate 2-active, Cstruct=0.00 (only 2 active
   workers). → PASS or FAIL depending on per-stream balance among
   the 12 streams.

Plus a **negative case**: take case 1 (balanced `{2,2,2,2,2,2}`) but
inject per-stream throughputs that violate the contract (e.g. one
stream gets <1% of the mean → starved-flow Gate 1 fails). Assert
`verdict == FAIL` and `failure_reasons` contains the expected
"starved" message.

### Implementation seam

`fairness-eval` is already a standalone binary that reads files and
emits a verdict. The fixture invokes it via `Command::new("./target/
release/fairness-eval").args(...)`. No production code changes;
purely test additions in:

- `userspace-dp/tests/fairness_fixture.rs` (new top-level integration
  test, ~200 LOC).
- `userspace-dp/Cargo.toml` (add `[[test]] name="fairness_fixture"`
  if needed; default integration-test discovery should pick it up).

Possibly also:

- `test/incus/fairness-fixture.sh` (new): a shell wrapper that
  invokes the same fixture via the `fairness-eval` binary on the
  cluster, so the cluster CI gets the same regression coverage as
  local cargo test. Optional; if the integration test runs in
  cargo, the cluster harness doesn't need to repeat it.

### Verdict-stability harness invariants

Each fixture case is parameterised by `(distribution_a_i,
per_stream_bps, expected_verdict)`. A change to either
`fairness.rs` or `fairness-eval` that changes the verdict on an
existing case must update the fixture in the same PR — the
fixture is the canonical "what the verdict means" pin.

## 4. Public API preservation

None. This PR adds tests only.

## 5. Hidden invariants the change must preserve

- `fairness-eval` exit code semantics: 0 PASS, 1 FAIL, 2 IO/parse
  error. Fixture must distinguish.
- Verdict JSON schema: 16 fields as of 6a00c7f5. Fixture must not
  rely on positional order.
- `fairness.rs::compute_cstruct` is the single source of truth for
  Cstruct. Fixture must not duplicate the formula — it must call
  `compute_cstruct` directly (already exposed via `mod fairness;`
  in main.rs and via `#[path = "../fairness.rs"]` in fairness-eval.rs).
- 6-col TSV format: `timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount`.
  Header line starts with `#`. Fixture must produce this format and
  exercise the `--iface` filter (legacy 3-col path is not the default
  but should also be unit-tested).

## 6. Risk assessment

| Risk class | Level | Note |
|---|---|---|
| Behavioral regression risk | LOW | tests-only PR; no production code touched |
| Lifetime / borrow-checker risk | LOW | the fixture builds Vec<u8> + writes to tempdir; no Arc/Mutex shenanigans |
| Performance regression risk | NONE | not on any hot path |
| Architectural mismatch risk | LOW | fixture parameterises an existing binary's inputs; no architectural surface |

## 7. Test plan

- [ ] `cargo test --release` — all 1006+31+8 existing tests pass + N new
  fixture cases (target: 6+ — 5 worked examples + 1 negative).
- [ ] `cargo test --release fairness_fixture` — named integration test
  passes 5/5 in a row (flake check).
- [ ] `go test ./...` — unchanged; tests-only PR.
- [ ] Manual: run on the loss userspace cluster after deploy as a
  smoke check that the fixture binary runs identically to the
  harness binary path. Optional; the integration test already covers
  this in cargo.
- [ ] No CoS smoke matrix needed — this PR doesn't touch dataplane.

## 8. Out of scope (explicitly)

- Synthetic packet generator that drives the BPF/userspace-dp
  flow_cache with controlled RSS distribution. (Different problem.)
- Cluster-level integration test that drives `iperf3 -P N` and then
  asserts the harness's verdict against the fixture's prediction. The
  cluster's RSS distribution is not deterministic enough for this;
  that's exactly why we have the fixture.
- Adding the fixture as a CI gate (no GitHub-side CI on this repo).

## 9. Open questions for adversarial review

1. **Is the fixture too thin?** It parameterises an existing binary's
   inputs and asserts known-correct output. A reviewer might argue
   this is just re-testing the unit tests in `fairness.rs::tests` at
   a higher integration level. Is that valuable, or is the unit-test
   coverage already enough?
2. **Should the fixture exercise the BPF + userspace-dp flow_cache
   path** instead of just `fairness-eval`? That would be much larger
   and would conflate fixture-correctness with dataplane-correctness.
   Plan defers; reviewers may PLAN-KILL if they think it's too
   shallow.
3. **Should the fixture be in `userspace-dp/tests/` or in
   `test/incus/`?** The cargo path runs locally + on developer
   machines; the incus path runs on the cluster. Plan picks cargo
   tests; reviewers may push for incus.
4. **TSV writer correctness**: a fixture that writes a malformed TSV
   would silently drop rows in `fairness-eval` (which uses
   `parts.len() == 6` matching, with anything else silently
   skipped). Should the fixture round-trip its own output through
   `parse_binding_flows_tsv` to assert the format is parseable
   before invoking the binary? Plan: yes, add an explicit assertion.
5. **Negative-case coverage**: 1 negative case (starved flow) covers
   Gate 1. Should we also exercise Gate 2 (CoV gap exceeds ε) and
   the saturated-only gate? Plan: yes, add 2 more negative cases.
6. **Brittleness vs the harness binary path**: if the fixture invokes
   `fairness-eval` via `Command`, it depends on the binary having
   been built. `cargo test` builds the binaries when the test
   declares them as a dependency, but reviewers may flag this as
   fragile vs an in-process call. Should the fixture call
   `fairness-eval`'s `main()` logic in-process (refactor needed) vs
   via subprocess?

## 10. Methodology

Per project triple-review discipline:

- v1 plan committed; Codex hostile + Gemini adversarial dispatched
  in parallel.
- Iterate until both PLAN-READY (or both PLAN-KILL — that's an
  acceptable outcome here).
- Implement; cargo test 5x flake check; open PR; wait for Copilot.
- Triple-review the code; merge on consensus.

PLAN-KILL is a real possibility for this PR. The fixture's value is
proportional to how much we expect future fairness-mechanism PRs to
cite it. If the project's per-5-tuple drive ends in Path 4
(workload-aware gate) without a Path 2 ship, the fixture's payoff is
small.
