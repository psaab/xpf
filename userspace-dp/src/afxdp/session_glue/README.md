# userspace-dp/src/afxdp/session_glue/

The bridge between an existing session table entry and a forwarding
resolution. Given a session's `SessionDecision` (NAT, drop, or
forward) and the cached `ForwardingResolution` from a prior packet
of the same flow, this module decides whether the cache is still
usable or the resolution must be re-derived.

Also writes the userspace dataplane's view of session state back
into the BPF session map mirror so the CLI / GC / metrics surface
sees the same sessions the userspace path is processing.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Cache-validation helpers (`cached_session_resolution`, `resolution_target_for_session`), `resolve_flow_session_decision`, `delete_terminal_filtered_session`, plus the BPF session-map mirror writers. |
| `promote.rs` | Synced-session hit handling: `maybe_promote_synced_session` (promote a peer-synced hit to locally-owned) and `purge_translated_synced_hit` (drop + NAT-release a transient alias-owned hit). |
| `commands/` | Worker-command handlers (`handle_upsert_synced`, `handle_delete_synced`, owner-RG refresh/demote/export). |
| `tests.rs` | Co-located unit tests for cache validation + mirror semantics. |

## Where it sits

- Called by the worker poll loop after `session::lookup` finds an
  existing session.
- Reads from `forwarding/` for resolution rebuild when the cache is
  stale.
- Writes to the BPF session map (via `coordinator/bpf_maps.rs` FDs)
  so the eBPF data-display surface mirrors the live userspace
  session table.

## Command ingest is budgeted (`apply_worker_commands`, #7201)

`apply_worker_commands` is the worker's consumer for its
`Arc<Mutex<VecDeque<WorkerCommand>>>` queue. It does **not** drain the
whole queue.

Each pass takes a contiguous FRONT prefix of at most
`worker_queue::WORKER_COMMAND_DRAIN_BUDGET` (256) commands into a
caller-owned scratch deque (`drain_bounded_into`), dispatches exactly
those, and returns `WorkerCommandResults.commands_backlogged` if the
shared queue still holds more.

Why, and what a change here must not break:

- **Every command is a session-table mutation plus a BPF-map publish
  syscall, and the worker does not touch its AF_XDP rings until the
  dispatch loop ends.** Batch size is therefore unserviced ring time.
  Draining the full #6929 queue cap of 4096 measured 3.85 ms against an
  RX ring that fills in ~1.97 ms at 25 Gbps — and the burst arrives at
  RG activation. Before #7201 this was `core::mem::take` of the whole
  deque and one uninterrupted `for` loop.
- **The prefix is contiguous and taken from the front,** so FIFO and the
  ordering groups survive a split by construction. The queue carries
  ordered state transitions (`UpsertSynced` then `DeleteSynced` for one
  key); a budget that filled its quota by skipping, or took from the
  back, would invert a key's state.
  `apply_worker_commands_dispatch_order_pin_with_demote_dedup` pins the
  order within one batch;
  `apply_worker_commands_7201_preserves_dispatch_order_across_a_budget_split`
  pins it across the seam.
- **`commands_backlogged` must reach `did_work` in
  `worker/loop_body`.** It is not a statistic. `did_work` is otherwise
  set only by `poll_binding`, so dropping this makes the budget worse
  than the defect: a promoted standby with no traffic yet runs
  `idle_iters` past `IDLE_SPIN_ITERS` and puts every remaining slice
  behind a 1 ms `poll(2)` in Interrupt mode.
- **The scratch deque is worker-owned and recycled** — entered empty,
  left empty. It is what removed the zero-capacity regrow: `mem::take`
  handed the worker the producers' allocation and left the shared deque
  at capacity 0 for the producers to rebuild under the lock every pass.
- Export acks stay monotonic across a split: `worker/loop_body` stores
  `exported_sequences.iter().max()` per pass, and FIFO makes each pass's
  max strictly greater than the last.

## A refused cross-worker `DeleteSynced` (#8114 item 4)

`replicate_session_delete` fans a `DeleteSynced` out to every sibling
worker's queue, and `push_bounded` REFUSES at
`MAX_PENDING_WORKER_COMMANDS` (4096) rather than evicting — the queue
carries ordered state transitions, so dropping from the front would
invert a key's state (see the section above).

A refused DELETE is not a missed optimisation. `handle_delete_synced` is
what a worker does with the command, and it drops **that worker's**
source-NAT and NAT64 holder bits; the port is freed by whichever worker
drops the last bit. A worker that never receives the command never drops
its bit, and it is ALIVE — so neither the dead-worker sweep (#8069) nor
the generation-teardown sweep (#7092) can see the bit. The reservation is
held for the life of the allocator. That is a port LEAK on top of the
stale-forwarding window #8114 names.

`replicate_session_delete_repairing` runs the two releases on the refused
worker's behalf, which is the worker-side twin of the repair
`Coordinator::delete_synced_session_gen` already does (#6979 F4). Three
things about it are load-bearing:

- **The worker id is resolved by `Arc` identity, not by position.**
  `peer_worker_commands` is built in `reconcile/bringup.rs` as
  `.filter(|(id, _)| **id != worker_id).map(|(_, queue)| queue.clone())`,
  so the ids are gone by the time the fan-out sees the slice, and its
  order relative to the id-keyed map depends on which worker is excluded.
  `WorkerContext::worker_commands_by_id` is asked "which id is THIS
  allocation?". A parallel `&[u32]` would be the same fact written down
  twice and would drift.
- **Only a REFUSED push is repaired.** When the push succeeds that worker
  will run the teardown itself, and freeing the port here would hand it
  to a new flow while the old one is still being torn down — the
  direction of error `PortAllocator::drop_holder_locked` forbids. This is
  also why "release for every worker id" is not a substitute for
  resolving the id.
- **An unresolvable id is counted, not guessed.** A caller with no id map
  (every pre-#8114 fixture) takes that path and behaves exactly as before.
  `SESSION_DELETE_REPLICA_DROPPED` minus
  `SESSION_DELETE_REPLICA_DROP_REPAIRED` is the unattributed remainder;
  the per-call `DeleteReplicationOutcome` is the same pair without the
  cross-test racing a process-wide counter has.

**The other half — the sibling's own session entry and flow-cache slots
— is repaired by the refused worker itself (#8586).** It is not reachable
from the deleting thread (both live behind that worker's `&mut
SessionTable` and its per-binding caches), and the signal cannot travel
through the queue that is full, so it goes out of band:

- `SESSION_DELETE_DROP_EPOCH[worker_id]` is bumped at the refusal, next
  to #8576's NAT repair and for the same resolved worker id.
- The worker loop compares it once per pass — one relaxed load — and on a
  change ARMS a `DeleteDropSweep`, which is then stepped on subsequent
  passes plus the flat flow-cache eviction. A burst raises exactly ONE
  sweep however many refusals it caused, because the epoch is compared
  and not counted down.

**The sweep is BUDGETED, and the epoch gate is not what makes that
unnecessary (#9327).** The gate bounds how OFTEN the sweep runs, not what
one run costs, and a single refused cross-worker `DeleteSynced` — ordinary
RG-activation churn — arms it. The unbudgeted whole-table walk, measured
on this tree:

```text
n=16384 finds-nothing   1.745 ms    <- already at the ~1.97 ms RX-ring fill
n=60000 finds-nothing   6.466 ms    <- 3x the fill
n=60000 all-stale      39.148 ms    <- ~20x the fill
```

The worker does not service its AF_XDP RX/TX rings while it sweeps, so
that is wall-clock time the rings go unserviced — the same unit and the
same justification as `WORKER_COMMAND_DRAIN_BUDGET`, which is 256 for
exactly this reason. `DEFAULT_MAX_SESSIONS` is 131072, so 60k is not the
ceiling. Note the *finds-nothing* case is the cheap one and it is already
over budget by 16k sessions.

`DELETE_DROP_SWEEP_BUDGET` is 256 slab slots per pass, matching the
command-drain budget so the worker keeps one batch granularity rather
than two, and the `stale` buffer is retained across passes so a steady
state performs no allocation (the previous code cloned every peer-synced
key into a fresh `Vec`, twice — at 60k sessions and a 52-byte key, two
~3.1 MB allocations on the worker loop, per firing).

Resumption is APPROXIMATE by design: slots freed mid-cycle can be reused
below the cursor and are not revisited until the next cycle. That is
acceptable here and would not be for an expiry walk — this sweep is a
convergence step whose miss is re-armed by the next epoch bump, and a
session wrongly retained for one more cycle is the same state the
pre-#9327 code held for the whole interval between bumps. Arming
mid-sweep RESTARTS rather than queueing, because the epoch says the
shared map changed and every slot already judged against the old map has
to be re-examined.

**Why the trigger is the DELETE drop and not queue pressure**, measured
rather than assumed (#8586, `loss:xpf-userspace-fw0`): ordinary session
establishment pins the queue at the 4096 cap and discards 85,668 commands
over 32,768 creates while dropping **zero** deletes — what is lost there
is `UpsertSynced` replicas, whose content the shared map still holds. A
trigger on queue depth would run the whole-table walk continuously
through normal traffic and reconcile nothing. The harmful loss is
confined to a revocation burst or an RG activation: one `clear security
flow session` over 32,770 entries refused 30,786 delete replicas, all
attributed and NAT-repaired (`dropped - repaired = 0`).

**Why the reconcile is scoped by `SessionOrigin::is_peer_synced()`**, and
the exclusions are the safety property:

- `SharedPromote` is EXCLUDED and is the one a reader expects to be in.
  It is synced-DERIVED but no longer peer-AUTHORITATIVE — the origin an
  entry receives after local traffic promoted it — so this node owns it
  and its absence from the shared map is not evidence it should die.
  `loop_body`'s "synced-derived, never create-counted" arm DOES include
  it; that classification answers a different question and using it here
  would be the bug.
- `FabricPuntSeed` and `MissingNeighborSeed` are transient-local by
  construction (never HA-exported, never Open-delta'd), so they are live
  local sessions ABSENT from the shared map by design. The naive "drop
  what the shared map does not have" sweep deletes them on its first
  pass; `is_peer_synced()` excludes them.

The reconcile releases no NAT, removes no shared state and replicates no
delete: the deleting worker already did all three (#8576), and repeating
any of them would double-process a pair or recurse. It holds the
shared-map lock across the membership FILTER only, never across the table
walk — sibling workers take that lock on their packet path.

**Still not covered:** a refusal whose worker id could not be resolved
bumps no epoch, because there is no worker to name. Those are the
`SESSION_DELETE_REPLICA_DROPPED - SESSION_DELETE_REPLICA_DROP_REPAIRED`
remainder, measured at 0 across 30,786 refusals.

`teardown_tcp_rst_flow` still uses the non-repairing
`replicate_session_delete`. It is currently unreachable —
`should_teardown_tcp_rst` returns `false` unconditionally — so wiring the
repair through it would be untestable code on a dead path; its drops are
counted.

## Terminal-filtered session teardown (`delete_terminal_filtered_session`, #5622)

When an *established* LocalDelivery session re-evaluates a terminal gate
on the session-HIT path and is now denied — host-inbound admission,
an lo0 input filter, or a `to-zone junos-host` policy (the three
`poll_descriptor` call sites) — the session is torn down. Because a
translated flow is TWO independent entries (forward `is_reverse=false`
+ reverse companion `is_reverse=true`) and the hit can land on EITHER,
the teardown must resolve and remove BOTH halves and release the
NAT pool reservation, exactly like the ordinary idle reap
(`worker/loop_body::reap_expired_sessions`) and the DSCP-filter purge
(`purge_sessions_for_input_dscp_filter_revalidation`) do per entry.

`delete_terminal_filtered_session` therefore:

- recovers the companion key with `reverse_session_key(key, decision.nat)`
  (its own inverse given the reversed decision, so it yields the forward
  key from a reverse hit and vice-versa — the same hop
  `companion_keeps_alive`/`account_packet` use);
- runs `delete_terminal_half` for the resolved key AND (if present) the
  companion. Each half releases its source-NAT / NAT64 allocation
  (`release_source_nat_allocation`/`release_nat64_allocation`, both
  self-gated on `is_reverse` and keyed on the forward flow — so the pair
  frees the reservation EXACTLY ONCE, no double free), deletes the live
  BPF session-map + conntrack aliases, drops the worker-local table entry
  and the shared HA maps, queues the cross-worker `DeleteSynced`, and
  emits its close delta (suppressed for the reverse half).

The DSCP purge no longer releases allocations separately — the helper
owns that now; `release_flow` is idempotent, so a caller that visits both
halves in turn stays correct. Before #5622 the helper deleted only the
supplied key and released nothing, leaking the same-worker companion
entry and the pool port on every translated LocalDelivery terminal deny.


## Deleted first-policy purge (`purge_sessions_bound_to_deleted_first_policy`, #9526)

The daemon's commit sweep clears a deleted policy's sessions by `policy_id`
(`pkg/daemon/daemon_policy_invalidate.go`), but it must skip id 0. The
literal first policy's id is also the value host-local, neighbor-seed, fabric,
tunnel and older-peer sessions carry. Those sessions were said to idle out.
For a one-way flow they did not: the #8356 re-derivation declines every
reverse packet, and reverse traffic keeps the forward half alive
(`companion_keeps_alive`), so a reverse-sustained flow kept transiting under
the deleted policy.

The helper has the discriminator the daemon lacks. A session a policy
admitted binds that rule's counter handle, and the overloaded-zero sessions
bind none. So on each forwarding-snapshot rotation the worker loop runs two
steps:

- **Before** assigning the new state, it asks
  `deleted_first_policy_rule_id(old, new)`. The answer is the old snapshot's
  single `policy_id` 0 rule, when the new snapshot no longer contains its
  stable id (the rule was deleted or renamed).
- **After** the assignment, it purges the forward sessions bound to that rule
  id with `delete_terminal_filtered_session`: both halves, NAT release, the
  shared HA maps, `DeleteSynced`, and a close delta the daemon turns into an HA
  peer delete.

The comparison costs O(rules) per rotation, and the session walk runs only
when the first policy actually vanished. A snapshot whose rules all carry 0
(ids never assigned) names no first policy and purges nothing. Only the
deleted half is covered: a MODIFIED first policy keeps its stable id, so
policy-rematch leaves it to the #8356 re-derivation. That covers every flow
that sends a forward packet (measured in #9596); the reverse-only residual is
#9604. The cells are in
`deleted_first_policy_purge_9526_tests.rs`. The worker-loop wiring is bound
behaviourally in `worker/loop_body/first_policy_purge_rotation_9526_tests.rs`:
the cells run the real `worker_loop` with an empty binding plan (no AF_XDP,
`BusyPoll`), install a bound session pair and an unbound id-0 session with
`UpsertLocal`, publish a real forwarding rotation, and read the coordinator's
shared HA map. A control rotation that keeps the first policy purges nothing.
## Transient synced-hit purge (`purge_translated_synced_hit`, #5295)

When a packet hits a peer-synced translated FORWARD session whose RG is
NOT locally active (`should_keep_synced_hit_transient` in `promote.rs`),
the hit is kept *transient*: the entry is purged from the worker table,
the shared HA maps, and the kernel session-map so the local node
re-resolves instead of forwarding to the wrong node. That purged entry is
a forward, peer-synced session, so at install `handle_upsert_synced`
RESERVED its translated `(pool_addr, port)` in this node's LOCAL
source-NAT / NAT64 allocator (`reserve_synced_source_nat_allocation` /
`reserve_synced_nat64_allocation`, #4388 / #4512) so a post-failover local
allocation cannot re-hand the same tuple.

Since #6211 the source-NAT reserve picks WHICH rule's allocator to use by
re-running the active node's own match predicate against the synced zone
pair + 5-tuple, instead of taking the first rule whose pool merely contains
the translated address (they differ only when two rules carry overlapping
pool addresses in separate allocators — see
`docs/session-sync-architecture.md`). Because selection is no longer a pure
function of `rules`, a session re-upserted after the selection outcome
changes can hold a reservation in TWO independent allocators, so
`release_source_nat_allocation` now frees from EVERY pool-mode rule rather
than stopping at the first hit. Stopping at the first hit stranded the other
reservation permanently. The sweep cannot over-free: `release_flow` /
`rollback_flow` return false unless the stored translated tuple matches.

#6979 F3: an accepted same-key REPLACEMENT releases the replaced session's
reservation before installing the new one — but only when the new entry will
not re-reserve the flow. Most replacements need nothing: `reserve_flow` is
keyed on the ORIGINAL 5-tuple (`SourceNatFlowKey` carries no translated
field), so a NAT -> different-NAT re-decision finds the incumbent under the
same flow and retires it with release semantics (#6528). The hole was the
replacement that never REACHES `reserve_flow` — the reserve is gated on
`is_peer_synced() && !is_reverse` at the call site and again on
`nat.rewrite_src.is_some()` inside
`reserve_synced_source_nat_allocation_with_holder` — so a NAT -> NO-NAT
re-decision (the active re-evaluates a reused 5-tuple after its NAT rule is
withdrawn), a flip to a reverse entry, or a peer-synced -> local-origin
replace installed the new session and stranded the old port forever:
delete-sync releases the CURRENT decision, which no longer names it.
`handle_upsert_synced` captures the previous `(decision, metadata)` before
`upsert_synced_with_origin` discards `_previous` and, when
`new_entry_reserves` is false, runs the SAME teardown pair delete-sync uses.
The condition is load-bearing in both directions: releasing unconditionally
would drop this worker's holder bit and re-take it on a same-tuple refresh
(HA sync reconnect, periodic re-upsert), opening a window for another
worker's local allocation to steal the port.

#6211 F2: the synced entry is fanned out to EVERY worker while the allocator
is one shared `Arc`, so N workers reserve the same `(flow, translated)` and
each releases it independently. `LiveAllocation.holders` (a `u128` bitmask
keyed on `worker_id`) makes the release free the port only when the LAST
holder lets go — before it, the first worker to reap or delete-sync freed a
port the other N-1 were still forwarding through. Every release site in this
module therefore takes a `worker_id`, threaded from
`WorkerLaunchPlan::worker_id` through `apply_worker_commands` /
`resolve_flow_session_decision` / `delete_terminal_filtered_session`, and calls
the `_for_worker` entry points; the untracked twins are `#[cfg(test)]` so
missing the thread is a build failure.

`purge_translated_synced_hit` therefore ALSO releases that reservation —
`release_source_nat_allocation` + `release_nat64_allocation`, under the
same `metadata.is_reverse` ownership guard used everywhere the reservation
is freed (reap, delete-sync, terminal-filtered teardown). The guard and
`release_flow`'s track-then-free contract make this safe against a
double-free: the purge fires only for the forward translated side
(`is_translated_forward_session_key` rejects reverse/alias keys), and
`release_flow` is a no-op when the flow was never tracked. Before #5295
the purge dropped the session state but released NOTHING, LEAKING the
reserved port on every alias-owned transient purge → standby source-NAT /
NAT64 pool exhaustion under sustained HA churn. Distinct from #5178 (a
reservation released into a recycle queue the deterministic allocator
never drains) — here there was simply no release call at all.
