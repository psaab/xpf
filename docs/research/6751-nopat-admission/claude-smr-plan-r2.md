# Claude SMR hostile plan review — #6751 plan v2 (round 2)

Reviewer: Claude SMR. Posture: hostile — re-derived every Codex r2 and AGY r2
finding against the worktree at `149cc4cfb` before believing any of them, then
attacked v2 on my own axis. Verdict at the bottom.

## Adjudication of the other two round-2 reviews (all verified, none taken on faith)

**AGY r2 blocker 1 (materialize bypass) — CONFIRMED REAL.**
`materialize_shared_session_hit` (afxdp/session_glue/mod.rs:1122-1145) calls
`sessions.upsert_synced_with_origin(...)` directly with
`origin = shared.origin.materialized_shared_hit_origin()`. It never touches
`reserve_synced_source_nat_allocation` (that call lives only in
commands/upsert_synced.rs:91, reached only via `WorkerCommand::UpsertSynced`).
A materialized replica is a real, reapable forwarding entry; the reap path
(loop_body/mod.rs:1625) releases unconditionally. Under v2's holder model the
materializing worker never joins the holder set, so owner-reap empties the set
and frees the identity while the materialized session still forwards. This is
the #6522 shape reproduced inside v2 — exactly what §5.6 claimed to prevent.

**AGY r2 blocker 2 (replace leaks the old tuple) — CONFIRMED REAL.**
`upsert_synced_with_origin`'s replace path removes the previous entry in-table
(session/install.rs:322 region) WITHOUT routing through
`release_source_nat_allocation`. If the replacement carries a different
translated tuple, v2's model +{W}s the new tuple but never −{W}s the old: a
permanent identity leak per tuple churn. The shipped `reserve_flow` already
solves the same problem for pools — on a tuple change it drops the stale
reservation first (allocator.rs:1666-1676). v2's interface reserve must mirror
that, with the holder decrement riding the drop.

**Codex r2 blocker 1 (tolerant-load + runtime-only addresses leave the seam
live) — CONFIRMED REAL.** The #5144 validator warns-only on tolerant load by
design ("the config still installs on the tolerant load / peer-sync path, but
the two allocators remain independent...", compiler_validate_strict_nat.go:2728-2734),
and the Go snapshot builder resolves interface addresses from the LIVE kernel
(`buildLinkSnapshot` via `net.InterfaceByName`, pkg/dataplane/userspace/interfaces.go:455-465),
so DHCP/externally-installed addresses can overlap a configured pool with no
config-visible evidence. A config-only validator cannot close this; the
foreclosure must ALSO exist at snapshot build, where both the pools and the
resolved runtime interface addresses are in hand, using the existing
fail-closed channel (`pool_failure`/`PoolUnusable`, nat_source.go:118-122).

**Codex r2 blocker 2 (shared publish precedes any reserve) — CONFIRMED REAL.**
The coordinator publishes the synced entry to the shared maps
(ha/session_import.rs:131-137) BEFORE fanning `UpsertSynced` out to workers
(:233). The decision is packet-reachable (shared lookup) before any holder
exists. v2's "keep #4388 graceful-skip" answer installs a known-open hole in a
NEW security invariant; Codex is right that the precedent is inherited risk,
not license. The fix is specifiable without touching the synced fast path:
reserve at the COORDINATOR before `publish_shared_session`; on identity
conflict, drop the import (count + Debug) instead of publishing — fail-closed,
one flow's sync sacrificed rather than a post-failover collision. Worker-side
reserve then idempotent-hits (+{W}).

**Codex r2 blocker 3 (all-workers-reap frees identity under a live shared
entry) — CONFIRMED REAL.** Peer-synced worker reaps emit no Close delta
(session/expire.rs:342-344 gate), so the shared-map entry outlives every
worker copy; v2's worker-only holder set empties, frees the identity, and a
later shared-map rematerialize resurrects the old session onto a claimed
tuple. Holder ownership must include the shared-map entry itself: +{"shared"}
at `publish_shared_session`, −{"shared"} at `remove_shared_session`. The fatal
sequence dies at step 4 (the shared flag still holds when workers drain).

**Codex r2 major 4 (lazy create atomicity + lifetime bounds) — CONFIRMED.**
`allocator_for` must be a single write-lock `entry(addr).or_insert_with(...)`
returning the stored winner. And "never dropped" + "config-bounded" is
contradictory under address churn: specify reclamation (allocator reclaimed at
snapshot-apply when the address is absent from the new egress set AND
`live_by_flow` is empty), a cumulative allocator cap (fail-closed mint beyond
it), and LOOKUP-ONLY release (a static/foreign decision's release must never
create an empty allocator).

**Codex r2 major 5 (probe math + hysteresis claims wrong) — CONFIRMED.**
`try_next_port` is deterministic round-robin (allocator.rs:944-958,
`counter.fetch_add(1) % range`), so the (D/64512)^4096 figure describes
nothing. A contiguous 4096-candidate occupied run false-exhausts with 60k
identities free, and an insider can SHAPE such runs (squat consecutive
ports) — the exact attacker the plan invokes for option (a). The #3011
recycle-FIFO comparison is likewise wrong (explicit queue, allocator.rs:508/621;
identity tokens never enter it). Required: exhaustive full-cycle probe from
the cursor (failure == genuine per-(addr,dst,dport) exhaustion, exact, no
probability), chunked across mutex acquisitions (64/CS, yield between, the
#4676 `gc_expired_chunked` precedent) to answer AGY r2 major 4's contention
point in the same move. Per-address mutex scoping (not global) bounds
contention further. Withdraw "never drops"/"statistically exhaustive" wording.

**Codex r2 major 6 (validator owner granularity) — CONFIRMED.** §5.7's
"one owner per interface-mode rule" would false-reject ordinary multi-rule
configs resolving to one WAN address. Owners must be deduped by ADDRESS (the
registry's actual ownership granularity), carrying rule refs only for the
diagnostic string.

**Codex r2 minor 7 (debug_log! is feature-gated) — CONFIRMED**
(afxdp/mod.rs:51, `#[cfg(feature = "debug-log")]`). §5.8's "observability via
debug_log" is not production observability. Combined with AGY r2 minor 6
(operators need counters for a High security change) and Codex r1 major 9
(no breaking API change), the resolution is: two ADDITIVE optional status
counters on the existing wire (`xpf_userspace_interface_snat_pat_collisions_total`,
`xpf_userspace_interface_snat_identity_exhaustion_total`) plumbed via the
#1760-W3' precedent (protocol/control.rs:343 + protocol_status.go:287);
additive per #1961 (old Go ignores, old helper omits).

**Codex r2 nit 8 (holder identity type) — CONFIRMED.** `BindingWorker.worker_id`
is `u32` and a worker owns multiple bindings (worker/mod.rs:108-112); the reap
sweep is worker/table-scoped. Holder set is `FxHashSet<u32>` of stable
`worker_id`, not "worker/binding index u16".

**AGY r2's own axes 1-3 resolution — CONFIRMED CORRECT.** Option (a) is the
right architecture (the (b)-squatting-DoS argument stands and AGY now accepts
it); §5.4's rejection of the r1 "mis-parse" claim stands
(protocol_ha.go:57 carries `NATSrcPort` generically);
§4-item-6's surfaces audit checks out on all four citations.

## My own additional round-2 findings

### M9 (MAJOR) — The sync-family install paths need ONE install+reserve wrapper, enumerated exhaustively

With AGY-1 (materialize) and the tunnel-prewarm `UpsertLocal` consumer
(session_glue/mod.rs:778-830, entries carry sync-family origins and bypass
reserve) both confirmed, acquisition-by-call-site is proven fragile: three
sync-family install sites exist (commands/upsert_synced.rs,
session_glue/mod.rs:1122 materialize, session_glue/mod.rs:778 UpsertLocal)
and two of three bypass. v3 must specify a single
`install_synced_with_reserve(...)` wrapper used by ALL THREE (install, then
reserve/+{W} for forward entries; `is_reverse` skips, nat/source.rs:789/874
gates), so "every sync-family install acquires" is structural, not a
per-site discipline reviewers must re-audit.

### M10 (MINOR) — Coordinator pre-reserve must gate is_reverse and ride bulk sync cost

The coordinator publishes reverse entries too (session_import.rs reverse_entry
arm); the pre-reserve must skip `is_reverse` (mirrors nat/source.rs:874).
Bulk sync of O(100k) sessions adds one mutex'd identity mint per entry on the
coordinator — cold path, throttled sweep, acceptable, but the plan should say
so explicitly.

### M11 (MINOR) — Delete-sync vs queued-upsert ordering leaves a bounded worker-holder tail

Coordinator delete (remove shared entry, −{"shared"}) can precede a still
queued `UpsertSynced` on some worker; that worker then installs +{W} for an
entry the peer already deleted, released only at the worker's own reap.
Bounded (entry lifetime), safe direction (identity held, not freed early) —
document, don't "fix".

### M12 (NIT) — §4 option (b) DoS wording should name the brute-force variant

The squatting DoS is not limited to a learned (port, server) pair: an insider
can iterate all 64512 source ports to one victim server and squat the WHOLE
space (cost: 64512 short-lived flows), denying a pinned-port victim
indefinitely under (b). Under (a) the victim still PATs around it. One
sentence strengthens the fork argument.

## Verdict

**PLAN-NEEDS-REVISION.** No finding challenges the architecture — Codex r2,
AGY r2, and this review all converge that option (a) is the right direction
and the identity-token redesign is sound. The three blockers (runtime overlap
foreclosure, transactional sync reserve, shared-map-aware holder ownership)
plus the enumerated majors are all foldable without redesign. v3 must ship:
snapshot-builder overlap foreclosure (pool_unusable-style fail-closed) atop
the deduped-by-address validator extension; coordinator pre-reserve with
drop-on-conflict; {"shared"} + {worker_id: u32} holder ownership with the
single install+reserve wrapper (M9); atomic lazy-create + reclamation + cap +
lookup-only release; exact full-cycle chunked probe; additive status counters;
the M10-M12 notes.
