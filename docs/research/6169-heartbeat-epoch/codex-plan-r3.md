Fail. v3 genuinely fixes several round-2 findings, but the persistence/election invariant and key-rotation linearization are still broken. A material redesign remains; this is not KILL-worthy, but Stage 1 is not implementable safely.

| Round-2 finding | v3 result |
|---|---|
| 1. Counter reset / anchor overstatement | Normal key rotation fixed; residual honestly documented. Cross-crash repeated epoch remains broken. |
| 2. TLV/bodyEnd ambiguity | Marker design is sound. Missing bounds and epoch-stripping logic remain. |
| 3. Persistence/election fence | Not resolved. The fence is volatile and its election semantics are unspecified. |
| 4. Re-prime / key TOCTOU | Clear-set and coordinated-key intent fixed. Packet effects still cross the K1→K2 boundary. |
| 5. #5639 | Hard sequencing is now real. The proposed owner is not yet a complete race-free design. |
| 6. Concurrency / durable I/O | Cold-boot I/O placement fixed. Key publication/reset/application transaction remains incoherent. |
| 7. Staging | Stage −1/0 split and discriminator boundary are fixed. Stage 1 remains unsafe. |

## Blocking findings

### 1. The volatile election fence does not make an unpersisted epoch safe across the next crash

Section 5.4 permits a node to send candidate `H` after persistence fails, relying on an in-memory election fence ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:240), [fence policy](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:260)). That fails under this legal schedule:

1. Disk contains valid `P`.
2. A1 calculates `H=P+1`; durable write fails before replacement.
3. A1 runs fenced but keeps sending `H`. B records `(H, highCounter)`.
4. A1 runs long enough for `highCounter` to exceed the heartbeat timeout horizon, then crashes.
5. A2 rereads `P`. With a non-advancing/regressed clock, it calculates the same `H=P+1`.
6. This write succeeds, so A2 declares READY. Its counter restarted at one.
7. B rejects A2 until its counter catches A1’s old high-water—potentially for as long as A1 ran.

A2 has lost A1’s volatile fence. A preempt RG can promote during the initial single-node election because the current fresh-boot hold excludes preempt mode ([election.go:419](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:419)). B rejects A2, times it out, and follows the single-node promotion path ([heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:404)). That can leave both primary.

This directly disproves §5.2’s assertion that the repeated-epoch case is safely fenced ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:188)). A safe design must either never emit an unpersisted epoch, or retain durable evidence that an unknown epoch may have escaped. An in-memory flag cannot do that.

The state-loss classification has the same flaw. `DELETED`, `UNREADABLE`, `CORRUPT`, and rejected far-future values all become `prev=0`; a successful write of `now` then declares READY ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:240)). If a peer previously recorded a higher value, that persists a lower epoch without fencing. Calling the old value “invalid” does not change the receiver’s high-water.

`classify(readFile(path))` also cannot distinguish `CLEAN_FIRST_BOOT` from `DELETED`: both are `ENOENT` without some independent durable provenance. The cited SNMP implementation instead fails closed on read, parse, arithmetic, or write uncertainty ([agent.go:573](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/snmp/agent.go:573)).

### 2. The election fence has no defined ownership semantics

The plan says the node advertises “fenced-secondary state” but never defines the actual wire state or election predicate ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:262)). That omission is load-bearing:

- Heartbeats advertise the raw RG state ([heartbeat_manager.go:266](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:266)).
- If a high-priority fenced node advertises ordinary `Secondary`, a healthy lower-priority peer also stays secondary under normal priority election ([election.go:247](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:247)).
- `SecondaryHold` explicitly tells the peer to take ownership, but currently means transfer-out ([election.go:160](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:160)). Reusing it requires precise dual-fenced semantics so two persist-failed nodes neither both promote nor remain permanently ownerless.

“Does not preempt” is also insufficient for an already-primary node. The existing kernel-upgrade fence explicitly demotes primaries when armed ([kernel_selfrecover.go:52](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:52)) and guards both peer-aware and single-node election paths ([election.go:44](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:44), [election.go:405](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:405)).

Finally, “confirmed absent” cannot merely mean `!peerAlive`; preempt currently bypasses the never-seen wait. Real confirmation occurs after the startup grace through `handlePeerNeverSeen` ([heartbeat_manager.go:450](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:450)). The plan still lists the exact hook as an open question ([plan §12.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:397)). A load-bearing election invariant cannot remain an open question in PLAN-READY.

### 3. The key-generation check still does not cover peer-state or election effects

V3 verifies K1, checks the generation under `admission.Lock`, updates `lastSeen`, unlocks, and only then invokes `handlePeerHeartbeat` ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:200)).

A stale application schedule remains:

1. K1 frame verifies and passes the generation check.
2. Admission unlocks.
3. Config apply publishes K2 and resets the admission floor.
4. The K1 packet then enters `handlePeerHeartbeat`, marks the peer alive, replaces all peer RG state, and runs election.

Those are exactly the substantial effects performed by the current handler ([heartbeat_manager.go:294](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:294)). Merely copying `pkt` into `snapshotPeerApply` does not linearize its later application.

The packet must carry its generation into the `m.mu` transaction and recheck before updating `lastSeen`, peer state, or election. Key/gen publication plus admission reset must likewise be one specified transaction; otherwise publishing K2 before reset can admit a K2 packet and then erase its watermark, making that same packet replayable.

### 4. Bring-up initialization misses supported live key activation

The cold-boot insertion point is real: epoch resolution can occur between `NewManager` and the first `UpdateConfig` election ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)). Heartbeat starts later ([daemon_ha_sync.go:767](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:767)). That part is fixed.

But §5.4 resolves only at bring-up “when keyed.” A Manager may boot unkeyed and enable authentication live:

- `UpdateConfig` publishes or clears the key and immediately elects ([group_state.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:85), [group_state.go:125](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:125)).
- The sender fetches the live key every tick without restarting ([heartbeat.go:723](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)).

No barrier initializes/persists the epoch or arms the fence before that key publication, election, and first signed send. V3 must either resolve epoch state for every Manager at construction, regardless of current key, or define a two-phase live key-enable transaction outside `m.mu`.

### 5. The concrete receiver algorithm omits the epoch-stripping gate

V3 stores and resets `sawEpoch`, but its concrete admission algorithm never checks:

```text
if !hasEpoch && sawEpoch => REJECT
```

Section 5.2 specifies the epoch comparison and then says v1 uses the ring ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:179)); §5.3 only sets `sawEpoch` after acceptance ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:202)).

As written, authenticated archived markerless frames continue into the 64-slot ring after v2 has been observed. That ring is explicitly churnable with 65 sessions ([heartbeat.go:495](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:495), [heartbeat.go:560](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:560)). Without the missing branch, Stage 1 does not close the named attack.

The tail reader also needs a mandatory `bodyEnd >= 16` check. The plan directly slices `bodyEnd-16` ([plan §5.1](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:138)), but a canonical zero-RG body is only 13 bytes: nine-byte header, monitor count, and three-byte version trailer ([heartbeat.go:206](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:206), [heartbeat.go:254](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:254), [heartbeat.go:279](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:279)). A replayed MAC-valid short v1 heartbeat can panic a literal implementation.

## What is genuinely fixed

The key-derived marker itself passes the re-attack:

- It is tail-anchored and checked only after the unchanged XPFA frame MAC verifies ([plan §5.1](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:118)).
- Existing XPFA authentication covers the complete body and nonce ([heartbeat.go:413](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:413), [heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)).
- Old receivers ignore bytes after the legacy version section ([heartbeat.go:361](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:361)).
- The keyless full-frame rule closes the unverified-`bodyEnd` regression ([plan.md:134](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:134)).

The marker is not literally “unforgeable”: it is visible on the wire, and an archived v1 body can naturally collide with probability approximately `q/2^64`. But under the stated passive-replay threat, an attacker cannot retrofit the marker into a captured v1 frame without invalidating its outer MAC. Using a distinct fixed HMAC input under the same key is acceptable under the HMAC PRF assumption. This is a probabilistic discriminator, not an architectural blocker.

The normal sender lifecycle is also fixed: Manager-scoped `{session,counter}` survives heartbeat restart and no longer resets on key rotation ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:164)). The post-restart single-admit window is now honestly documented ([plan §6](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:295)).

Counter exhaustion remains only a slogan, however. “Force a fresh epoch” does not define how sending is quiesced, the new epoch durably committed, or the counter and legacy session atomically replaced ([plan.md:169](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:169)). Resetting the counter while retaining the session wedges a v1 receiver at its `MaxUint64` watermark.

The re-prime clear set is correct: retaining `peerAuthSeen`, the ring, and sender nonce avoids reopening cleartext ([plan §5.5](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:276)). The never-used cluster-wide key requirement is also cryptographically correct.

## #5639 and staging

V3 now makes #5639 a genuine hard prerequisite rather than falsely claiming it is subsumed ([plan §3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:75), [plan §8](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:342)). That resolves the sequencing finding.

The prerequisite’s acceptance criteria still need strengthening. Current heartbeat auth state belongs to the replaceable receiver ([peer_state.go:29](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:29)), while sync auth reads and sets SessionSync-local state ([sync_auth.go:139](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:139), [sync_auth.go:415](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:415)). A shared Boolean alone is insufficient: a cleartext sync handshake can read `false`, then heartbeat can arm the owner, and the handshake can still install a long-lived unauthenticated connection afterward. #5639 needs a commit-time owner-generation recheck or active draining of pre-arm cleartext connections.

Stage 0 is independently valuable after Stage −1: Manager nonce ownership plus the cap policy closes upgraded-peer routine-restart churn. The marker genuinely removes v2’s mandatory key-rotation rollout boundary. Those improvements justify continuing rather than killing the effort.

Stage 1 nevertheless needs a major revision and new tests for:

- persist-fail → emit → crash → same epoch persisted successfully;
- deleted/unreadable/corrupt state plus backward clock;
- preempt startup, dual persist failure, lower-priority healthy-peer takeover, and peer-return demotion;
- K1 acceptance paused across K2 reset and eventual election application;
- live empty→key activation;
- `sawEpoch && !hasEpoch`;
- authenticated short v1 bodies;
- counter rollover through an injectable boundary.

The cost/benefit remains positive because the threat is credible and Stage 0 has independent value. But the claimed F3 and F4 resolutions are not real, and the persistence failure is in the total-order foundation itself.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
199,184
Fail. v3 genuinely fixes several round-2 findings, but the persistence/election invariant and key-rotation linearization are still broken. A material redesign remains; this is not KILL-worthy, but Stage 1 is not implementable safely.

| Round-2 finding | v3 result |
|---|---|
| 1. Counter reset / anchor overstatement | Normal key rotation fixed; residual honestly documented. Cross-crash repeated epoch remains broken. |
| 2. TLV/bodyEnd ambiguity | Marker design is sound. Missing bounds and epoch-stripping logic remain. |
| 3. Persistence/election fence | Not resolved. The fence is volatile and its election semantics are unspecified. |
| 4. Re-prime / key TOCTOU | Clear-set and coordinated-key intent fixed. Packet effects still cross the K1→K2 boundary. |
| 5. #5639 | Hard sequencing is now real. The proposed owner is not yet a complete race-free design. |
| 6. Concurrency / durable I/O | Cold-boot I/O placement fixed. Key publication/reset/application transaction remains incoherent. |
| 7. Staging | Stage −1/0 split and discriminator boundary are fixed. Stage 1 remains unsafe. |

## Blocking findings

### 1. The volatile election fence does not make an unpersisted epoch safe across the next crash

Section 5.4 permits a node to send candidate `H` after persistence fails, relying on an in-memory election fence ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:240), [fence policy](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:260)). That fails under this legal schedule:

1. Disk contains valid `P`.
2. A1 calculates `H=P+1`; durable write fails before replacement.
3. A1 runs fenced but keeps sending `H`. B records `(H, highCounter)`.
4. A1 runs long enough for `highCounter` to exceed the heartbeat timeout horizon, then crashes.
5. A2 rereads `P`. With a non-advancing/regressed clock, it calculates the same `H=P+1`.
6. This write succeeds, so A2 declares READY. Its counter restarted at one.
7. B rejects A2 until its counter catches A1’s old high-water—potentially for as long as A1 ran.

A2 has lost A1’s volatile fence. A preempt RG can promote during the initial single-node election because the current fresh-boot hold excludes preempt mode ([election.go:419](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:419)). B rejects A2, times it out, and follows the single-node promotion path ([heartbeat_manager.go:404](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:404)). That can leave both primary.

This directly disproves §5.2’s assertion that the repeated-epoch case is safely fenced ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:188)). A safe design must either never emit an unpersisted epoch, or retain durable evidence that an unknown epoch may have escaped. An in-memory flag cannot do that.

The state-loss classification has the same flaw. `DELETED`, `UNREADABLE`, `CORRUPT`, and rejected far-future values all become `prev=0`; a successful write of `now` then declares READY ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:240)). If a peer previously recorded a higher value, that persists a lower epoch without fencing. Calling the old value “invalid” does not change the receiver’s high-water.

`classify(readFile(path))` also cannot distinguish `CLEAN_FIRST_BOOT` from `DELETED`: both are `ENOENT` without some independent durable provenance. The cited SNMP implementation instead fails closed on read, parse, arithmetic, or write uncertainty ([agent.go:573](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/snmp/agent.go:573)).

### 2. The election fence has no defined ownership semantics

The plan says the node advertises “fenced-secondary state” but never defines the actual wire state or election predicate ([plan §5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:262)). That omission is load-bearing:

- Heartbeats advertise the raw RG state ([heartbeat_manager.go:266](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:266)).
- If a high-priority fenced node advertises ordinary `Secondary`, a healthy lower-priority peer also stays secondary under normal priority election ([election.go:247](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:247)).
- `SecondaryHold` explicitly tells the peer to take ownership, but currently means transfer-out ([election.go:160](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:160)). Reusing it requires precise dual-fenced semantics so two persist-failed nodes neither both promote nor remain permanently ownerless.

“Does not preempt” is also insufficient for an already-primary node. The existing kernel-upgrade fence explicitly demotes primaries when armed ([kernel_selfrecover.go:52](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/kernel_selfrecover.go:52)) and guards both peer-aware and single-node election paths ([election.go:44](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:44), [election.go:405](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:405)).

Finally, “confirmed absent” cannot merely mean `!peerAlive`; preempt currently bypasses the never-seen wait. Real confirmation occurs after the startup grace through `handlePeerNeverSeen` ([heartbeat_manager.go:450](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:450)). The plan still lists the exact hook as an open question ([plan §12.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:397)). A load-bearing election invariant cannot remain an open question in PLAN-READY.

### 3. The key-generation check still does not cover peer-state or election effects

V3 verifies K1, checks the generation under `admission.Lock`, updates `lastSeen`, unlocks, and only then invokes `handlePeerHeartbeat` ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:200)).

A stale application schedule remains:

1. K1 frame verifies and passes the generation check.
2. Admission unlocks.
3. Config apply publishes K2 and resets the admission floor.
4. The K1 packet then enters `handlePeerHeartbeat`, marks the peer alive, replaces all peer RG state, and runs election.

Those are exactly the substantial effects performed by the current handler ([heartbeat_manager.go:294](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:294)). Merely copying `pkt` into `snapshotPeerApply` does not linearize its later application.

The packet must carry its generation into the `m.mu` transaction and recheck before updating `lastSeen`, peer state, or election. Key/gen publication plus admission reset must likewise be one specified transaction; otherwise publishing K2 before reset can admit a K2 packet and then erase its watermark, making that same packet replayable.

### 4. Bring-up initialization misses supported live key activation

The cold-boot insertion point is real: epoch resolution can occur between `NewManager` and the first `UpdateConfig` election ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)). Heartbeat starts later ([daemon_ha_sync.go:767](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:767)). That part is fixed.

But §5.4 resolves only at bring-up “when keyed.” A Manager may boot unkeyed and enable authentication live:

- `UpdateConfig` publishes or clears the key and immediately elects ([group_state.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:85), [group_state.go:125](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:125)).
- The sender fetches the live key every tick without restarting ([heartbeat.go:723](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)).

No barrier initializes/persists the epoch or arms the fence before that key publication, election, and first signed send. V3 must either resolve epoch state for every Manager at construction, regardless of current key, or define a two-phase live key-enable transaction outside `m.mu`.

### 5. The concrete receiver algorithm omits the epoch-stripping gate

V3 stores and resets `sawEpoch`, but its concrete admission algorithm never checks:

```text
if !hasEpoch && sawEpoch => REJECT
```

Section 5.2 specifies the epoch comparison and then says v1 uses the ring ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:179)); §5.3 only sets `sawEpoch` after acceptance ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:202)).

As written, authenticated archived markerless frames continue into the 64-slot ring after v2 has been observed. That ring is explicitly churnable with 65 sessions ([heartbeat.go:495](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:495), [heartbeat.go:560](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:560)). Without the missing branch, Stage 1 does not close the named attack.

The tail reader also needs a mandatory `bodyEnd >= 16` check. The plan directly slices `bodyEnd-16` ([plan §5.1](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:138)), but a canonical zero-RG body is only 13 bytes: nine-byte header, monitor count, and three-byte version trailer ([heartbeat.go:206](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:206), [heartbeat.go:254](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:254), [heartbeat.go:279](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:279)). A replayed MAC-valid short v1 heartbeat can panic a literal implementation.

## What is genuinely fixed

The key-derived marker itself passes the re-attack:

- It is tail-anchored and checked only after the unchanged XPFA frame MAC verifies ([plan §5.1](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:118)).
- Existing XPFA authentication covers the complete body and nonce ([heartbeat.go:413](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:413), [heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)).
- Old receivers ignore bytes after the legacy version section ([heartbeat.go:361](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:361)).
- The keyless full-frame rule closes the unverified-`bodyEnd` regression ([plan.md:134](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:134)).

The marker is not literally “unforgeable”: it is visible on the wire, and an archived v1 body can naturally collide with probability approximately `q/2^64`. But under the stated passive-replay threat, an attacker cannot retrofit the marker into a captured v1 frame without invalidating its outer MAC. Using a distinct fixed HMAC input under the same key is acceptable under the HMAC PRF assumption. This is a probabilistic discriminator, not an architectural blocker.

The normal sender lifecycle is also fixed: Manager-scoped `{session,counter}` survives heartbeat restart and no longer resets on key rotation ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:164)). The post-restart single-admit window is now honestly documented ([plan §6](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:295)).

Counter exhaustion remains only a slogan, however. “Force a fresh epoch” does not define how sending is quiesced, the new epoch durably committed, or the counter and legacy session atomically replaced ([plan.md:169](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:169)). Resetting the counter while retaining the session wedges a v1 receiver at its `MaxUint64` watermark.

The re-prime clear set is correct: retaining `peerAuthSeen`, the ring, and sender nonce avoids reopening cleartext ([plan §5.5](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:276)). The never-used cluster-wide key requirement is also cryptographically correct.

## #5639 and staging

V3 now makes #5639 a genuine hard prerequisite rather than falsely claiming it is subsumed ([plan §3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:75), [plan §8](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:342)). That resolves the sequencing finding.

The prerequisite’s acceptance criteria still need strengthening. Current heartbeat auth state belongs to the replaceable receiver ([peer_state.go:29](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:29)), while sync auth reads and sets SessionSync-local state ([sync_auth.go:139](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:139), [sync_auth.go:415](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:415)). A shared Boolean alone is insufficient: a cleartext sync handshake can read `false`, then heartbeat can arm the owner, and the handshake can still install a long-lived unauthenticated connection afterward. #5639 needs a commit-time owner-generation recheck or active draining of pre-arm cleartext connections.

Stage 0 is independently valuable after Stage −1: Manager nonce ownership plus the cap policy closes upgraded-peer routine-restart churn. The marker genuinely removes v2’s mandatory key-rotation rollout boundary. Those improvements justify continuing rather than killing the effort.

Stage 1 nevertheless needs a major revision and new tests for:

- persist-fail → emit → crash → same epoch persisted successfully;
- deleted/unreadable/corrupt state plus backward clock;
- preempt startup, dual persist failure, lower-priority healthy-peer takeover, and peer-return demotion;
- K1 acceptance paused across K2 reset and eventual election application;
- live empty→key activation;
- `sawEpoch && !hasEpoch`;
- authenticated short v1 bodies;
- counter rollover through an injectable boundary.

The cost/benefit remains positive because the threat is credible and Stage 0 has independent value. But the claimed F3 and F4 resolutions are not real, and the persistence failure is in the total-order foundation itself.

VERDICT: PLAN-NEEDS-MAJOR
