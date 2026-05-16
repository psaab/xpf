# userspace-dp/src/fairness_eval/

Orchestration library for the `fairness-eval` binary.

The binary is intentionally a thin CLI shell. This module owns the
evaluation pipeline from parsed args and loaded inputs through steady-state
windowing, per-worker active-flow aggregation, RSS expectation checks,
verdict construction, and JSON report emission.

Keep behavior compatible with `userspace-dp/tests/fairness_eval_blackbox.rs`:
CLI flags, exit codes, TSV parsing, JSON fields, and failure-reason ordering
are the public contract.
