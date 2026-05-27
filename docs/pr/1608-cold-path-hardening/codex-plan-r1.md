# Codex hostile plan-review r1 — #1608

**Reviewer:** Codex (task-mpoiqsu3-3pmepo). Captured here verbatim from
the Codex `rendered` output because the Codex sandbox refused
`apply_patch` to the worktree (read-only mount as far as the helper
saw). Synced to disk by the driver agent for the smoke-runner contract.

**Verdict: PLAN-KILL**

## Findings (verbatim)

- **FATAL:** Per-source CLI semantics are false with per-worker AF_XDP
  state. Kernel docs confirm RSS spreads packets across receive queues
  by L3/L4 hash, and AF_XDP sockets are bound to a single queue. A
  random-source-port flood from one source becomes `rate * worker_count`,
  not `rate`.

- **FATAL:** The proposed insertion point is wrong.
  `resolve_flow_session_decision` is session lookup, not policy eval;
  actual policy scan is later at `poll_descriptor/mod.rs:1375`.

- **FATAL:** Verdict key lacks `to_zone_id`; policy eval keys on
  `from_id` and `to_id`.

- **MAJOR:** #1431 cache-key invariant is not actually incorporated.
  DSCP is a concrete cache-sensitive miss; TCP flags/frags are
  documented future cache-sensitive fields.

- **MAJOR:** Cargo bench cannot validate RSS spread, RX ring pressure,
  or driver behavior for a 1 Mpps wire flood.

- **FATAL:** Storage budget fails by measured Rust layout: source table
  ~160 KB, verdict table ~256 KB, combined ~416 KB before extras.

- **MAJOR:** HA failover wipes buckets/cache during the exact threat
  window.

## Recovery path (verbatim)

Rewrite the plan before implementation. Rename semantics to
per-source-per-worker or add shared/sharded enforcement, move the
verdict cache to the real policy-eval site, key the full policy tuple,
wire #1431 gates/tests, redo packed storage with `size_of` tests, and
require a wire/RSS acceptance test.

---

## Driver-agent comment

Codex finds two additional FATALs that the Claude SMR pass missed:

1. **Insertion point is wrong** — the plan placed the gate at
   line ~605 in `poll_descriptor/mod.rs`, right before
   `resolve_flow_session_decision`. But that resolver is the SESSION
   lookup (not policy eval). The real policy scan that the cache is
   trying to skip is much further down the slow path. This re-frames
   the verdict-cache design: it has to live next to the actual policy
   linear scan, not at the session-lookup hand-off. The implementation
   cost goes up; the design becomes "skip the policy scan" not "skip
   session lookup."

2. **Verdict key missing `to_zone_id`** — policies are evaluated per
   zone-pair (`from_zone`, `to_zone`); two flows with identical
   4-tuples but different egress-zone resolutions get DIFFERENT
   policies. The cache as keyed would return wrong verdicts on any
   topology with cross-zone egress ambiguity. Must add `from_zone_id`
   AND `to_zone_id` to the key — which makes the key 42 → 46 bytes
   and pushes the storage math even further over budget.

Three independent reviewers (Claude SMR / Codex / AGY) converge on
PLAN-KILL. Three different fatal axes (per-worker RSS spray; wrong
insertion point + missing zone_ids; refill truncation + storage
overflow). No single round-2 plan can recover all of them without
substantially redesigning the mechanism.
