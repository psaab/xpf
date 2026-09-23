# Issue #9506: counter slice

## Scope

Rust-only post-merge follow-up on `b71c52d60`. The D13 ECN refusal now has one
canonical `AtomicU64`; the former lowercase definition is a crate-visible alias.
A single relaxed-load snapshot covers the twelve Rust-incremented IPsec-inner
and D11 queue/slab/verdict/orphan counters. `ProcessStatus` carries additive,
defaulted snake_case fields, and `refresh_status` projects one snapshot into
the status payload. No wire-version bump, Go edits, E28 changes, or live
cluster runs.

Read-only Go inspection found the existing decoder and Prometheus collector
mapping for `worker_command_queue_drops`; none of the twelve new keys has a Go
status field or collector mapping yet. Go decoder/collector mapping is therefore
a separate follow-up slice, not part of this Rust change.

## Verification ledger

| Check | Result |
| --- | --- |
| `cargo test --no-run` in `userspace-dp` | PASS |
| `ipsec_inner_ecn_alias_is_the_canonical_cell_9506` | PASS (1) |
| `refresh_status_projects_ipsec_inner_counters` | PASS (1) |
| `process_status_ipsec_inner_counters_serialize_under_snake_case_keys_9506` | PASS (1) |
| Full `server::tests` module, serial | PASS (149) |
| `ipsec_inner_queue` regression filter, serial | PASS (20) |
| `ipsec_inner_verdict_bridge` regression filter, serial | PASS (2) |
| `reinject_9506` regression filter, serial | PASS (66) |
| Red-on-revert projection probe | PASS: temporarily replacing the ECN projection with `= 0` failed with `left: 0`, `right: 17`; mutation restored and focused test passed |

All process-global test counters are restored before assertions. No formatter,
linters, project-wide suite, push, PR, or live-cluster command was run.
