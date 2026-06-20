# Plan of Action — #2003: split `afxdp/bpf_map/mod.rs` into pin/metrics/ha

**Recommendation: PLAN-KILL (already shipped).**

The refactor #2003 describes was already implemented and merged to
`origin/master` before this research run. PR **#2026**
(`refactor/2003-bpf-map-split`, merge commit `7c3905c9e`, merged
2026-06-19T04:46Z) performed exactly the suggested split. The only
residual action is administrative: **issue #2003 is still OPEN because the
PR body referenced `#2003` without a `Closes`/`Fixes` keyword, so GitHub
did not auto-close it.**

Branch for this research artifact: `research/2003-bpfmap-split`
(base `origin/master` @ `9979a89a0`).

---

## 1. Problem Statement / Goal

Issue #2003 (agy-review-013 Part II.2, LOC verified @ `b1ef3ed16`) asked to
split `userspace-dp/src/afxdp/bpf_map/mod.rs` (then 1063 LOC) into a thin
coordinator `mod.rs` plus three focused submodules:

```
bpf_map/
  mod.rs       # coordinator + init
  pin.rs       # sysfs dir cleanup + fd pinning
  metrics.rs   # telemetry / ring-metrics publishing
  ha.rs        # redundancy-group active validation
```

Stated rationale: the monolith mixed init, libbpf fd pinning, directory
cleanup, active-HA-state check, and ring-buffer telemetry publishing,
which made map interactions hard to unit-test without kernel deps.
Behavior-preserving code motion only.

## 2. Current State (verified on `origin/master` @ `9979a89a0`)

The split **already exists on master**. `bpf_map/` now contains:

| file | LOC | role |
|------|-----|------|
| `mod.rs` | 657 | coordinator: session-map publish/delete core, conntrack-mirror orchestrators, BPF conntrack struct mirrors, `mod`/re-export wiring |
| `ha.rs` | 155 | HA liveness slots — `register_xsk_slot`, `update_heartbeat_slot`, `delete_xsk_slot`, `delete_heartbeat_slot`, `maybe_touch_heartbeat`, `touch_heartbeat`, `heartbeat_fresh` |
| `metrics.rs` | 244 | telemetry/diagnostics — `diagnose_raw_ring_state`, `count_bpf_session_entries`, `dump_bpf_session_entries`, publish counters (`SESSION_PUBLISH_VERIFY_OK/FAIL`, `SESSION_PUBLISH_ERRORS_SHARED`, `SESSION_CREATIONS_LOGGED`, `ICMPV6_EMBED_LOGGED`) |
| `pin.rs` | 95 | libbpf fd pinning — `OwnedFd` (+ `open_bpf_map`/`Drop`), `DEGRADED_PATH_STATS_PIN_PATH`, `DEGRADED_PATH_REASON_NAMES`, `read_degraded_path_stats` |
| `publish_conntrack.rs` | 435 | pre-existing sibling (#1356), the cited precedent |

Provenance — three behavior-preserving code-motion commits, all ancestors
of `origin/master`:

- `4e85613f1` — `#2003: extract HA liveness slots into bpf_map/ha.rs`
- `de0219990` — `#2003: extract telemetry counters + diagnostics into bpf_map/metrics.rs`
- `70d5516b7` — `#2003: extract fd pinning + degraded-path reader into bpf_map/pin.rs`

`mod.rs` lines 641-657 already carry the `#2003` module-doc comment and the
`mod ha; mod metrics; mod pin;` + `pub(in crate::afxdp) use {ha,metrics,pin}::*;`
wiring.

### Deviation from the issue's suggested layout (immaterial)

The issue's column for `pin.rs` listed "sysfs **dir cleanup** + fd
pinning." The shipped `pin.rs` holds fd pinning and the pinned
degraded-path stats reader. There is no standalone "sysfs directory
cleanup" cluster in this file to extract — bpffs pin-directory lifecycle
is owned elsewhere in the coordinator, not in `bpf_map/mod.rs`. The
shipped grouping (fd pinning + pinned-path reader together, since both are
the only items that touch bpffs pin paths) is the correct cohesion. This
deviation is a refinement of the suggestion, not a gap. Concretely, the
residual `mod.rs` contains no directory-cleanup primitive to orphan —
`grep -nE 'rmdir|remove_dir|unlink|remove_file|fs::remove|std::fs'
bpf_map/mod.rs` returns nothing, so there is no stranded "sysfs dir
cleanup" cluster that should still move out.

## 3. Root Cause / Why Open

The work is done; the issue is stale-open. PR #2026's
`closingIssuesReferences` is empty: the title/body said `#2003` but used no
auto-closing keyword. Mechanical, not technical.

## 4. Options Considered

- **A — Re-implement the split.** Rejected: it already exists; re-doing it
  would be a no-op diff or a churning reorganization of an already-clean
  result, violating "behavior-preserving code motion only" by adding risk
  for zero benefit.
- **B — Further sub-split `mod.rs` (657 LOC).** Rejected: 657 LOC is far
  below the project's ~2,000 LOC split threshold
  (`docs/engineering-style.md` §"Modularity discipline"). The residual
  `mod.rs` is the coherent coordinator core (publish/delete + conntrack
  mirror + struct mirrors). Splitting further would scatter tightly
  coupled session-map logic. Out of scope and counter-productive.
- **C — PLAN-KILL + close the issue.** **Selected.** Recognize the work as
  shipped, document it, and close #2003 with a pointer to PR #2026.

## 5. Proposed Change (administrative only)

No production source change. The single recommended action:

- Close issue #2003 as completed, referencing PR #2026 / merge
  `7c3905c9e` and commits `4e85613f1`, `de0219990`, `70d5516b7`.

This research run does **not** close the issue autonomously (per task
scope: stop at a drafted plan + SMR; no PR). The draft comment posted to
#2003 records the finding for the maintainer to action.

## 6. Behavior-Preservation Argument

Already proven by the merged PR, re-verified here:

- **Visibility unchanged.** Original items were `pub(super)`
  (= `pub(in crate::afxdp)` for this file). Moved items keep
  `pub(in crate::afxdp)`, re-exported via
  `pub(in crate::afxdp) use {ha,metrics,pin}::*;`. Every consumer resolves
  unchanged: the parent `afxdp` glob (`use self::bpf_map::*`), bare-name
  call sites, the relocated `bpf_map_tests.rs` (`use super::*`), and the
  explicit external paths.
- **External explicit-path consumers verified intact** (grep on master):
  - `crate::afxdp::bpf_map::OwnedFd` — `coordinator/worker_manager.rs:69-70`,
    `coordinator/bpf_maps.rs:5`
  - `crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED` —
    `session_glue/promote.rs:113`, `forwarding/mod.rs:1136`

  All resolve through the re-exports; no path edits were needed at the call
  sites, confirming a non-widening, name-stable move.
- **No logic/signature/cfg change.** Each submodule's doc header asserts
  verbatim motion incl. `cfg(feature = "debug-log")` gating; PR validation
  recorded `cargo build --release` clean and `cargo test --release` lib
  2057 passed / 0 failed (+ other test binaries 0 failed).

## 7. Test / Validation Plan

For the PLAN-KILL itself, no source builds are required. **This research
run performed static + git verification only** (full read of `mod.rs`,
`grep` of the external explicit-path consumers and of dir-cleanup
primitives, `git merge-base` ancestry, `gh pr view` MERGED state); it did
not execute `cargo build`/`cargo test`. The build/test confirmation is
therefore the maintainer's re-run step. To independently re-confirm the
merged state is healthy (optional — this research run makes no production
edits):

```bash
cd userspace-dp
cargo build --release      # expect clean (pre-existing warnings only)
cargo test  --release      # expect 0 failed
```

Cluster smoke / `make test-failover` are **not** warranted: this is pure
intra-crate code motion already merged and already smoke-clean per PR
#2026. No HA/VRRP/session-sync/forwarding behavior is touched.

## 8. Risk Assessment

- **Technical risk: none.** No code change is proposed.
- **Process risk: low.** Closing a stale issue. The only way to get this
  wrong is to mistake "issue OPEN" for "work undone" and re-implement —
  this plan explicitly prevents that.
- **The Go import-cycle wall that killed sibling refactors #2002/#2004
  does not apply here.** This is a Rust intra-crate sub-module split;
  `mod {ha,metrics,pin};` under one crate has no module-graph cycle
  constraint, and the re-export pattern keeps every path stable. (This was
  the precise concern the task asked to verify — verified: not applicable,
  and the merged result proves cohesion held.)

## 9. Rollback

N/A — no change introduced by this research run. (Had the split needed
reverting, `git revert 70d5516b7 de0219990 4e85613f1` would restore the
monolith; not recommended — the split is clean and merged.)

## 10. Documentation Impact

None required for the (already-merged) code motion: the issue mandated
behavior-preserving motion, and the per-file module-doc headers added in
PR #2026 already document each submodule's role. No README/design/state/
operator doc references `bpf_map`'s internal layout (internal helper
module, `pub(in crate::afxdp)` surface only). This research artifact
(`docs/pr/2003-bpfmap-split/`) is the only doc produced.

## 11. Open Questions / Follow-ups

- **Action for maintainer:** close #2003 (point to PR #2026). The draft
  comment on the issue states this.
- **Peer backlog items #1986–#1990 and #2005** (the latter already MERGED
  via PR #2028, `session/mod.rs` → lookup/install/expire) are the sibling
  modularity targets; #2003 joins #2005 as completed. No coupling to this
  plan.
- **Process note for the tracker:** PRs that should close an issue must use
  a `Closes #N` keyword in the body — #2026 referenced `#2003` plainly and
  left it dangling open. Worth a one-line tracker hygiene reminder, not a
  code change.
