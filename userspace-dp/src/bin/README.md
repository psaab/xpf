# userspace-dp/src/bin/

Standalone binaries that link against the crate but aren't the
dataplane helper.

## Binaries

- `fairness-eval` (`fairness-eval.rs`) — consumes `iperf3 -J` output
  plus a Prometheus scrape of `xpf_userspace_binding_active_flow_count`
  or class-specific `xpf_userspace_cos_active_flow_count` and emits a
  fairness-regime verdict (Cstruct, observed CoV, starved flows). The
  optional `--rss-expectation` gate fails structurally skewed runs that
  violate an explicit workload contract even when scheduler fairness is
  within `Cstruct`. `fairness-eval.rs` is only the CLI shell; the
  evaluator pipeline lives in `src/fairness_eval/`. The merge bar for any
  fairness-mechanism PR is a PASS from this binary against the loss
  userspace cluster.

  Black-box discipline: cargo integration tests in `tests/*.rs` exercise
  the binary via `env!("CARGO_BIN_EXE_<name>")`, which prevents tests
  from reaching internal types and keeps the contract textual.

  See PR #1220 (harness shipped) and PR #1223 (fixture) for
  acceptance-test plumbing.
