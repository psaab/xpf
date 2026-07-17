# Codex — hostile plan review r2 (v4/Path C) — #5858 (verdict: PLAN-NEEDS-MAJOR)

# VERDICT: PLAN-NEEDS-MAJOR Path C is directionally better, and the current filter-classifica...

# VERDICT: PLAN-NEEDS-MAJOR

Path C is directionally better, and the current filter-classification flags do not leave a static-deny gap. But v4 is not implementation-ready. Reverse ingress is not knowable at forward install, deletion is not pair-aware, targeted cache eviction is underspecified and incomplete across workers, and the HA fallback/failover contract remains materially open.

## 1. Re-audit of the six r1 BLOCKINGs

| r1 finding | Status | Assessment |
|---|---|---|
| 2. Rotation gap | **PARTIALLY** | v4 now honestly states per-worker cutover and queued-TX residual, but does not prevent already-queued transmission. |
| 3. Flow cache | **NOT** | The proposed `evict_flow_cache(key)` cannot address the actual per-binding `(key, physical ingress_ifindex)` cache identity, and sibling deletion can bypass owner-side eviction. |
| 4. HA deletes at scale | **NOT** | Reverse-only denial emits no Close, `denied > 4096` is the wrong threshold, and no Rust→Go BulkSync trigger/completion path is designed. |
| 5. Failover window | **NOT** | v4 explicitly retains it, and the window is not necessarily bounded or self-healing because config enqueue/apply can fail. |
| 6. Permitted SNAT destruction | **PARTIALLY** | Fixed for an isolated purely-static precise walk, but mixed changes still family-purge permitted flows, and the proposed one-entry deletion has broken NAT ownership semantics. |
| 7. Telemetry-only purge | **RESOLVED** | The verdict-only mode on the exhaustive destructure is sound, provided the new tuple evaluator itself is side-effect-free. |

### r1 finding 2 — PARTIALLY, non-blocking only if the weaker cutover contract is accepted

Plan §7 correctly says cutover is per-worker, not globally atomic, and admits queued TX after rotation ([plan.md:329](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:329)). That matches independent worker Arc observation at [loop_body/mod.rs:372](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:372).

The actual residual remains: pending TX drains at [lifecycle.rs:70](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/lifecycle.rs:70), while Close-driven queued-flow cancellation occurs only after the packet sweep at [loop_body/mod.rs:961](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:961). Path C neither receives the pending queues nor cancels them directly.

The documentation overclaim is fixed; strict post-commit revocation is not.

### r1 finding 3 — NOT RESOLVED, BLOCKING

Plan §5.4 says eviction can be done by “the same 5-tuple / flow hash” and pseudocodes `evict_flow_cache(e.key)` ([plan.md:252](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:252), [plan.md:215](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:215)). That is not the real cache key:

- The set hash includes `SessionKey` and the physical ingress ifindex at [flow_cache.rs:759](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:759).
- Lookup validates both at [flow_cache.rs:868](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:868).
- `invalidate_slot` requires both at [flow_cache.rs:979](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:979).
- Caches are per `BindingWorker`; the proposed function signature has no bindings/cache context ([plan.md:182](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:182)).

There is an existing correct pattern: loop every binding and invoke `invalidate_slot(key, binding.ifindex)`, because the session lacks physical-ingress identity ([loop_body/mod.rs:1332](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1332)). This is safe: invalidation checks both fields, and the session table permits only one live session per 5-tuple.

Even that does not make owner-side eviction sufficient. `DeleteSynced` removes a sibling worker’s session without cache access at [delete_synced.rs:9](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:9). Commands are processed after forwarding rotation at [loop_body/mod.rs:584](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:584). A sibling can:

1. Read old forwarding.
2. Receive/apply the owner’s delete.
3. Retain its cache entry.
4. Rotate next iteration, when the session is already absent from the precise walk.

Therefore either `DeleteSynced` must return keys for all-binding cache eviction, or coherent generation refresh must remain load-bearing. The current “targeted eviction alone fully closes finding 3” claim is false.

### r1 finding 4 — NOT RESOLVED, BLOCKING

Three separate holes remain.

First, a reverse-only denial produces no HA Close. `delete_terminal_filtered_session` calls the explicit close emitter at [session_glue/mod.rs:479](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:479), but that emitter immediately returns for reverse metadata at [install.rs:460](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/install.rs:460). The standby’s synced pair has stamp `-1`, so it cannot independently repair this.

Second, `denied > 4096` is not the overflow predicate ([plan.md:282](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:282)). Overflow depends on current ring occupancy plus new forward Close deltas; `push_delta` drops when the current length is already at capacity ([session/mod.rs:1656](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/mod.rs:1656)). Even a much smaller deny set can overflow.

Third, the fallback is not designed end-to-end. `SessionSync.BulkSync` is a Go operation producing a lossless authoritative `BulkStart`/`BulkEnd` window ([sync_bulk.go:50](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_bulk.go:50)). The Rust revalidation function merely returns a count. No signal, aggregation across workers, ordering after local deletion, retry, error handling, or BulkAck requirement is specified.

The second Go-stage queue is also bounded at 4096 and the delete journal at 10,000 ([sync.go:597](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync.go:597), [sync.go:619](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync.go:619)). A per-worker threshold cannot reason about aggregate pressure.

Finally, BPF deletes still discard return codes at [bpf_map/mod.rs:569](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/bpf_map/mod.rs:569). This matters if an authoritative bulk reads a stale map entry and re-advertises it.

### r1 finding 5 — NOT RESOLVED, BLOCKING

The plan explicitly retains the failover hole ([plan.md:295](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:295)) and scopes out fencing ([plan.md:411](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:411)).

Worse, the description “bounded by config-sync latency; self-heals” is false:

- Config receipt is enqueued non-blockingly and can be dropped at [sync_conn.go:1632](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_conn.go:1632).
- Config apply can fail, leaving the old generation active until a later push at [sync_conn.go:1175](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_conn.go:1175).
- There is no matching apply acknowledgement to the primary.
- The planned-demotion barrier only orders session messages already queued; it does not prove config apply or worker revalidation ([daemon_ha_userspace_readiness.go:181](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/daemon/daemon_ha_userspace_readiness.go:181)).

Deleting the old synced tuple is not durable while the standby retains the old permitting config: after failover it may cold-reinstall the same tuple.

For the stated High security-revocation contract, failover must be fenced on successful peer config application plus revocation completion. Keeping the window requires explicit product sign-off on a weaker guarantee; documentation alone cannot resolve the r1 blocker.

### r1 finding 6 — PARTIALLY RESOLVED, BLOCKING mechanics remain

The isolated purely-static branch does preserve permitted entries at [plan.md:203](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:203). That fixes the r1 fresh-cursor problem for that branch.

But the global statement “permitted flows are never touched” is false:

- Mixed filters are routed to the existing family purge ([plan.md:162](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:162)).
- That purge selects every session of the family at [session_glue/mod.rs:345](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:345) and releases their SNAT allocations at [session_glue/mod.rs:355](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:355).

Therefore a mixed static edit or purely-static→mixed transition still drops permitted SNAT flows and may remap them. This is pre-existing behavior, but it invalidates the broad invariant and the “SNAT-safe” Path C table.

There is also a new lifecycle error: the plan attributes NAT/NAT64 release to `delete_terminal_filtered_session` ([plan.md:211](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:211), [plan.md:336](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:336)). The helper actually deletes only one key and performs no NAT release at [session_glue/mod.rs:446](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:446). Source-NAT release separately no-ops for a reverse entry at [source.rs:789](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/nat/source.rs:789).

Implemented literally, denied forward entries leak NAT allocations. Adding a naive release creates the opposite bug: the forward allocation may be freed while the reverse companion still uses it.

### r1 finding 7 — RESOLVED, with one new invariant

The verdict-only mode on the same exhaustive, `..`-free destructure is correct ([plan.md:232](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:232), [cache_sensitive.rs:308](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:308)).

However, `static_input_filter_verdict` must be explicitly side-effect-free. Reusing `evaluate_interface_filter` would record a counter packet even with `packet_bytes == 0`, because the evaluator records every matching counted term at [eval.rs:139](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/eval.rs:139), and `record_filter_counter` increments the packet count at [filter/mod.rs:696](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/mod.rs:696). One commit could fabricate one hit per revalidated session.

## 2. PURELY-STATIC versus mixed partition

The current match-classification model is gap-free.

- DSCP is aggregated from every term’s `dscp_match_enabled` at [compiler.rs:143](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/compiler.rs:143).
- `has_per_packet_l4_match()` covers required/forbidden TCP flags, fragments, ICMP type/code, and flexible match at [filter/mod.rs:261](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/mod.rs:261).
- The detectors inspect both old and new sides and then compare all terms at [cache_sensitive.rs:439](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:439) and [cache_sensitive.rs:506](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:506).

Thus:

- `from address X tcp-flags syn then discard` is mixed and family-purged.
- Purely-static→mixed is caught from the new-side flag.
- Mixed→purely-static is caught from the old-side flag.
- I found no current term shape whose static deny falls through both detectors.

But it is not overlap-free operationally. The mixed detector returns a per-family boolean at [loop_body/mod.rs:392](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:392). A mixed change on interface A purges all sessions of that family, including sessions on purely-static interface B changed in the same commit. The precise path may subsequently find nothing, but permitted B sessions were already destroyed.

There is also no compile-time completeness invariant on `has_per_packet_l4_match()`. A future packet-dependent `FilterTerm` field can be added without forcing this method to classify it, unlike the exhaustive comparator.

## 3. Dual-direction stamping and pair teardown — BLOCKING

The reverse ingress is not knowable at forward installation. Plan §5.1 assumes forward egress equals reverse ingress ([plan.md:140](/home/ps/git/bpfrx/.claude/worktrees/5858-research/docs/research/5858-input-filter-invalidation/plan.md:140)).

At install time, the code knows only the forward resolution and constructs the NAT-adjusted reverse tuple before any reply packet supplies ingress metadata ([poll_descriptor/mod.rs:3074](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3074), [poll_descriptor/mod.rs:3100](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:3100)). The authoritative reverse ingress exists only on the actual reply’s `meta.ingress_ifindex + ingress_vlan_id`, resolved at [filter.rs:342](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/filter.rs:342). The dataplane explicitly supports asymmetric-routing midstream pickup at [poll_descriptor/mod.rs:649](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:649).

Concrete bypass: forward exits B, reply enters C, reverse entry is stamped B, then a purely-static deny tightens on C. The C changed set skips the B-stamped reverse entry, and the static session hit continues.

Additionally, deleting a denied entry does not revoke the flow. Forward and reverse are independent entries; `delete_terminal_filtered_session` deletes only its argument. A whole-flow operation must:

- Canonicalize/deduplicate the forward and reverse keys.
- Delete both entries.
- Evict both keys from every binding cache.
- Cancel queued work for both keys.
- Release NAT/NAT64 exactly once using the forward entry.
- Emit the forward Close even when the denial was discovered on the reverse entry.

Without actual-ingress observation/update semantics and pair-level teardown, dual-direction coverage is false.

## 4. Other new Path C risks

- **BLOCKING:** the broad-deny BulkSync fallback is only named, not architected.
- **BLOCKING:** reverse-only denial currently emits no cross-node Close.
- **BLOCKING:** cache eviction lacks binding context and misses sibling-delete interleavings.
- **Non-blocking pending measurement:** the walk scans the entire session table, not merely affected sessions. It then performs term and prefix-vector matching for affected entries. This executes synchronously before packet polling, so a full 131,072-entry table can experience a commit-induced RX stall. Require a worst-case benchmark and an explicit stall budget before rating performance LOW.
- **Non-blocking:** enumerate every transit constructor, including missing-neighbor seeds and lazy shared reverse materialization. “Every transit install” is broader than the main forward/reverse constructor.
- **Non-blocking:** update the manual `SessionMetadata::PartialEq` implementation at [entry.rs:134](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/entry.rs:134); adding a struct field does not force that equality logic to classify it.
- **Resolved:** local-only wire exclusion is feasible. The real cross-node event encoder is field-by-field at [session_sync.rs:15](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/event_stream/codec/session_sync.rs:15), so omitting the new field does not require a wire-format change.

Path C is salvageable, so this is not PLAN-KILL. It needs another substantial design revision covering actual reverse-ingress identity, pair-aware teardown, all-binding/sibling cache invalidation, authoritative HA resync signaling, and failover fencing.
