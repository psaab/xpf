# Codex hostile plan review — #2852 r1

Verdict: **PLAN-NEEDS-MAJOR**

The v2 fold is superficially incomplete: the changelog accurately lists four
adopted findings but the body sections they reference were not actually
updated. The plan as written would send an engineer off building the wrong
thing on F2 (FIFO) and F3 (phasing). A new finding (F5 — lock-ordering
deadlock in persistent release/rollback) is real, neither the original plan
nor the Claude SMR caught it, and it blocks PLAN-READY.

---

## Verified-correct claims (not re-disputed)

- **Bottleneck location:** `allocator.rs:166 live: Mutex<PortAllocatorLiveState>`;
  held 336–475 in `allocate_translation`. Confirmed.
- **Per-new-flow, not per-packet.** `poll_descriptor/mod.rs:815` session-miss
  gate is the correct entry point. The PLAN-KILL line is honest.
- **Shared-allocator path:** `coordinator/ha_state.rs:14`
  `Arc<ArcSwap<ForwardingState>>` → `source.rs:261 pool_allocator` →
  `Arc<PortAllocatorShared>`. Confirmed shared across all workers.
- **sticky_pool_index lock-free:** `allocator.rs:836` pure function. Address-
  persistence unaffected by sharding. Confirmed.
- **Reverse-NAT from session table:** `ha.rs:420
  reverse_session_key(&entry.key, entry.decision.nat)`. Confirmed; allocator
  sharding cannot break it.
- **HA reservation correction (§7.5):** `debug_seed_owner` /
  `debug_clear_owner` are `#[cfg(test)]` only (`allocator.rs:230,239,259`);
  no production reserve call exists anywhere in `ha.rs` or `ha_state.rs`.
  Claim is correct. HA out-of-scope is right.
- **Persistent shard key correctness:** shard key = `hash(proto, src_ip,
  src_port)` (persistent key minus `remote`). `source.rs:172–185`
  `persistent_source_key` shows `AnyRemoteHost→remote=None`,
  `TargetHost→Some((dst,0))`, `TargetHostPort→Some((dst,dst_port))`. All
  three permit modes: the `remote` field distinguishes entries within a
  shard but all entries for the same `(proto,src,sport)` land in the same
  shard, so no lease is split. Shard key is correct for all three modes.
- **F1 (SMR) — conditional bit-clear / ABA:** AGREE. The
  `existing.translated != translated` guard at `allocator.rs:620–624` in the
  current `release_flow` is the correct precedent. The new design must
  replicate it: clear the bitmap bit ONLY when the matching record removal
  succeeds under the shard lock. See finding F1 below.
- **F2 (SMR) — cursor-wrap ≠ FIFO:** AGREE. Current code is a one-shot
  forward sweep (`next_offset >= range → break`, lines 502–519) followed by
  FIFO drain of `recycled_ports_by_addr` (`pop_front`, lines 530–542). A
  wrapping cursor is not equivalent — a port freed just ahead of the cursor is
  re-probed almost immediately; oldest-freed-first is NOT preserved. F2 is
  real and correctly diagnosed.
- **F3 (SMR) — phase the work, bitmap first:** AGREE. Bitmap claim is the
  dominant serializing work; map sharding is incremental. Phasing is the right
  call.
- **F4 (SMR) — global cap reserve/rollback discipline:** AGREE. A racy
  load-then-add on `live_flow_count` leaks slots. Must be
  fetch_add-reserve → fetch_sub on failure.

---

## Findings

### F-BODY (MAJOR) — v2 fold is changelog-only; body sections not updated

The v2 status section claims F1–F4 were folded with references to §5.2 item 3,
§5.3, §5.4, §7.1, §7.6, and §9 test 1b. None of these references are
satisfied by the actual body text:

- **§5.4 (F3 phasing) does not exist.** The section list is 5.1/5.2/5.3/6/7….
  The plan still says Phase 1 and Phase 2 exist (in the changelog) but §5.2
  and §5.3 describe the full two-tier sharding layout as the baseline, not a
  phased Phase 1 → Phase 2 sequence.
- **§5.3 still shows the full sharding struct** (`flow_shards: [Mutex<FlowShard>; N]`,
  `persist_shards: [Mutex<PersistShard>; N]`). No single-tiny-mutex Phase 1
  variant appears anywhere in the body.
- **§5.2 item 3 still asserts** "recycled_ports_by_addr (the FIFO 2MSL
  spreader) is replaced by the advancing cursor" — directly contradicting
  the v2 changelog which says "the design keeps a lock-free recycle ring by
  default." The body was not updated for F2.
- **§7.6 (F4 cap discipline) does not exist.** §7 has items 1–9; §7.6 is
  "Exhaustion accounting is exact pool-full" (pool-level, not the
  AtomicUsize fetch_add/fetch_sub reserve protocol that F4 requires).
- **§8 risk table and §6** still say "~185 white-box tests inspect old fields;
  broad mechanical rewrite." The v2 changelog correctly corrects this to ~32
  of the 185 tests, but §8 and §6 were not updated.
- **§9 test 1b** is referenced in the v2 changelog (conditional bit-clear
  regression test) but does not appear in §9. §9 still has items 1–7 with
  no 1b.

An engineer implementing from this plan would: delete the recycle queue (F2
contradiction in body), build the full two-tier shard layout from day one (F3
phasing ignored), and have no specified Phase 1 vs Phase 2 gate.

**Required action:** update the body (§5.2 item 3, §5.3 → Phase 1 struct,
add §5.4 Phase 2 description, §7.6 cap discipline, §8 risk table, §9 test
1b). The changelog must match the body, not substitute for it.

---

### F5 (MAJOR, new finding) — lock-ordering deadlock in persistent release/rollback

The plan asserts "fixed global order (persist-shard before flow-shard), always,
with no other nested order" (§7.9). This is false for `release_flow` and
`rollback_flow`.

**The ordering inversion:** `allocate_translation` (persistent path) acquires:
(1) persist-shard, (2) flow-shard. But `release_flow` must discover the
`persistent_key` from `live_by_flow` — which is behind the flow-shard — before
it knows which persist-shard to take. Naïvely: (1) flow-shard, (2)
persist-shard. That is the reverse order. Under concurrency:

- Worker A: allocating a persistent flow. Holds persist-shard[i], waiting
  for flow-shard[j].
- Worker B: releasing a persistent flow with src landing on shard[j] for
  flow-shard and shard[i] for persist-shard. Holds flow-shard[j], waiting
  for persist-shard[i].
→ **Deadlock**.

The current code avoids this because there is exactly ONE lock and the
persistent_key is read from live_by_flow while already holding it
(`allocator.rs:627 existing.persistent_key`).

**Possible resolutions (plan must pick one and state it):**

(A) **Always pre-take persist-shard at hash(proto,src_ip,src_port) BEFORE
flow-shard in release/rollback, even for non-persistent flows.** Non-
persistent callers pay a trivial lock acquire/release. Maintains the fixed
order. Adds persist-shard contention to the non-persistent release hot path
(measure — likely acceptable since release is typically ~1× the new-flow
rate at steady state). This is the cleanest structural fix.

(B) **Change `release_flow`/`rollback_flow` signatures to accept
`persistent_key: Option<PersistentSourceKey>`.** Callers (`source.rs:904/960`)
already have the persistent_key at the time of release. Avoids the speculative
shard lock. Breaks the "unchanged signatures" claim in §6. The claim is an
internal-module method (`pub(super)`), so it is not a public API break.

(C) **Store the persist_shard_index in `LiveAllocation` and expose it via a
separate lock-free atomic or struct field.** More complex.

(A) or (B) are tractable. The plan must specify which, and the deadlock-
freedom loom test in §9.6 must explicitly exercise the concurrent
allocate+release persistent path.

The §7.9 deadlock-freedom claim is unsubstantiated until this is resolved.

---

### F1-body (MINOR) — conditional bit-clear stated vaguely in body

The v2 body §5.2 item 3 says "cleared exactly once, by the legitimate owner."
This is closer than v1 but still ambiguous about MECHANISM. The body should
state the invariant from the SMR explicitly: *"the occupancy bit is cleared
exactly once, by the code path that successfully removes the owning
`live_by_flow` entry (non-persistent) or the lease record (persistent),
under that record's shard lock, conditioned on the matching translated-tuple
check (analogous to `existing.translated != translated` at `allocator.rs:622`)
— never unconditionally."* Add test 1b to §9: double-release and stale-tuple
release must NOT free a port owned by an unrelated live flow.

---

### F2-body (MINOR, blocked by F-BODY) — body still asserts cursor replaces FIFO

As noted above, §5.2 item 3 still claims the advancing cursor "replaces"
`recycled_ports_by_addr`. The v2 changelog says keep the recycle ring by
default. The body must say: default implementation keeps a **lock-free recycle
ring** (MPMC ring or equivalent) drained before forward-probing; the
cursor-only variant is a lab-gated alternative gated by the §9 test 8
regression (free N ports, assert the just-freed port is the LAST to be
reused). Until lab proves cursor-only is safe, the ring is mandatory.

---

### F4-body (MINOR, blocked by F-BODY) — cap reserve/rollback protocol not in body

§7.6 and §5.3 do not describe the fetch_add/fetch_sub reserve/rollback
discipline. Must add to both:

```
live_flow_count.fetch_add(1, Ordering::AcqRel);
// ... attempt bitmap CAS + shard insert
// on any failure:
live_flow_count.fetch_sub(1, Ordering::AcqRel);
return Err(AllocatorExhausted);
```

The over-cap check must be `fetch_add`→compare→fetch_sub on failure (never
racy load-then-add). This is a production correctness property; state it in
the design body and add a test that races cap-boundary allocations and asserts
the final count never exceeds the cap.

---

## SMR finding disposition

| Finding | Verdict | Evidence |
|---------|---------|----------|
| F1 — conditional bit-clear / ABA | **AGREE** | `allocator.rs:620–624` guard is the precedent; v2 body states intent vaguely — restate explicitly |
| F2 — cursor-wrap ≠ FIFO recycle | **AGREE** | `allocator.rs:502–542` confirms one-shot sweep + FIFO; wrapping cursor is not equivalent |
| F3 — phase the work: bitmap first | **AGREE** | Phasing is the right sequencing but §5.4 doesn't exist; body must be updated |
| F4 — global cap reserve/rollback | **AGREE** | §7.6 absent; must specify fetch_add/fetch_sub protocol in body |

No disagreements with F1–F4. All four are confirmed real.

---

## §7.5 HA-reservation verdict

**CORRECT, confirmed.** `debug_seed_owner`/`debug_clear_owner` are
`#[cfg(test)]` at `allocator.rs:230/239/259/260`. No production call to any
reservation path exists in `ha.rs` or `ha_state.rs`. The redesign's obligation
is "preserve current behavior" (no bitmap reservation of synced tuples at
failover). Out-of-scope is the right call. A follow-up issue for
HA-reservation hardening is warranted.

---

## What the plan and Claude SMR both missed

**F5 (deadlock)** is the only finding neither document addressed. It is real
and MAJOR (a loom test will reproduce it). Both documents assert deadlock
freedom from the fixed lock order without examining how `release_flow` discovers
the `persistent_key` — the critical step that creates the inversion.

---

## Disposition

The architecture (bitmap ownership, two-tier shard keys, phased delivery,
FIFO recycle ring, global atomic cap) is sound. The plan cannot go to
implementation because: (1) the body does not reflect the v2 changelog
(F-BODY — an engineer implementing from the body would build the wrong thing);
(2) F5 is a real deadlock that must be resolved in the design before any code
is written. Fix F-BODY (update §5.2/5.3/5.4/7.6/8/9) and resolve F5 (pick
resolution (A) or (B) and state it) → the plan reaches PLAN-READY-pending-lab.
The mandatory lab gate and PLAN-KILL line remain correct and should not be
weakened.
