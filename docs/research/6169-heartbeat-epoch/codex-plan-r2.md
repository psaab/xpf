Fail. v2 fixes the ordinary heartbeat-restart case only under an unchanged key. F3, F4, and F5 remain materially open, and the key-rotation design introduces new critical races.

| Area | Result |
|---|---|
| F1 / unchanged XPFA | Resolved |
| F2 tuple guard | Correct primitive, broken lifecycle |
| F5 TLV parsing | Not resolved for archived/mixed-version frames |
| F3 persistence | Not resolved; DEGRADED is not an election fence |
| F4 lifecycle/re-prime | Routine restart fixed; recovery remains unsafe |
| Concurrency | No basic lock deadlock, but key-reset TOCTOU is critical |
| Stage 0 | Valuable, but not independently shippable as specified |

### 1. §5.2 closes routine restart churn only if the counter never resets at the same epoch

The positive result is real: if `session/counter` are created once on `Manager`, routine `RestartHeartbeat` cannot reset them. `StartHeartbeat` stops the previous sender before installing its replacement ([heartbeat_manager.go:44](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:44)), and sender shutdown joins its run loop ([heartbeat.go:742](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:742)). A full daemon reboot creates a new Manager ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)), so a new v1 session still re-anchors normally through the ring’s unseen-session branch ([heartbeat.go:574](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:574)).

But the plan then contradicts its own proof:

- §5.2 says session/counter reset on auth-key rotation ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:190)).
- The same section claims counter reset occurs only with a strictly higher daemon epoch ([plan.md:212](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:212)).
- Key rotation is in-process, so the epoch remains `E` while the counter returns to one.
- §5.5’s explicit reset set then omits session/counter entirely ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:293)).

Those are two different designs. Resetting produces repeated `(E,1...)`, so `(epoch,counter)` is no longer the claimed total order. The correct simplification is to separate local send-nonce state from receiver `peerAdmission` and never reset the Manager counter merely because the key changes. Counter exhaustion must also be defined.

A full receiver daemon restart still resets `highEpoch=0`. An archived retired frame can therefore be accepted first and drive election before the live higher epoch arrives. §5.6 acknowledges the anchor window ([plan.md:309](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:309)), but that means the framing “retired incarnation can never be replayed” and “closes daemon-reboot churn” is overstated. The live frame repairs the floor later; it does not undo election effects already triggered.

### 2. §5.1’s TLV remains ambiguous for authenticated v1 captures

The typed TLV fixes the v2-to-v2 canonical case. It does not fix rolling deployment or archived captures produced by the uncapped v1 marshaler.

A concrete MAC-valid v1 body:

- One group, three monitors, software version `dev`.
- First monitor name is 256 bytes. Its encoded length wraps to zero because the marshaler writes `uint8(len(nameBytes))` while copying the complete name ([heartbeat.go:260](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:260)).
- Choose bytes so the desynchronized parser consumes two fake 84-byte monitors and a fake 100-byte version section.
- Exactly these ten bytes remain before XPFA:

```text
01 08 01 65 03 64 65 76 01 00
```

That is syntactically `[ExtType=1][ExtLen=8][eight epoch bytes]`.

The old frame remains HMAC-valid because the unchanged MAC covers the entire malformed body ([heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)). A Stage-1 receiver treats it as epoch-bearing, bypasses the v1 ring, advances `highEpoch`, and latches `sawEpoch`; subsequent canonical v1 frames are rejected as epoch stripping under [§5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:221).

Stage 0 cannot retroactively canonicalize captures. They remain valid under the unchanged PSK forever. The design needs one of:

- a mandatory fleet-wide Stage-0 deployment followed by a never-before-used key rotation before Stage 1;
- a key-derived extension discriminator that an old sender cannot accidentally produce;
- or another wire discriminator whose validity does not depend on successfully parsing the legacy variable-length body.

The caps also need an actual policy. “Cap/reject” is not a decision when `MarshalHeartbeat` still returns no error ([plan §7](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:361)). Five RGs with 54 one-byte monitor names each yield 270 monitor records and still fit under 1472 bytes with TLV and XPFA. A 255 cap silently drops 15 accepted monitor records. Choose upstream commit rejection or deterministic truncation with rate-limited warning and telemetry.

The TLV grammar must additionally define exact consumption, duplicate epoch behavior, unknown-TLV ordering, and trailing junk. “Invalid means no epoch” is safe only after these rules and only for frames from the new canonical sender.

There is also a new keyless regression: `heartbeatAuthTrailer` recognizes XPFA using only four bytes at `len-52` ([heartbeat.go:445](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:445)). §5.3 truncates to `bodyEnd` before semantic parsing. A canonical unkeyed body can naturally place `"XPFA"` at that offset, causing the new receiver to truncate a legitimate body even though no MAC can validate the supposed trailer. Only a verified MAC may authorize `bodyEnd`; the keyless path must parse the complete legacy frame.

### 3. §5.4’s DEGRADED path is not safe; it needs an election fence

The retryable initializer is only correct if it explicitly stores `{initialized, epoch, persisted, lastError}`. The pseudocode reloads and recomputes `cand` on each invocation ([plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:251)); prose later asserts that the value is fixed once ([plan.md:273](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:273)). That invariant must exist in the state machine, not commentary.

More seriously, DEGRADED is not a safety transition:

1. A fails to persist `H` but sends it; B records `H`.
2. A reboots from stale/lost state with a regressed clock and emits `L <= H`.
3. B rejects every A heartbeat and times it out.
4. Ordinary RG readiness does not demote an existing primary ([election.go:322](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:322)) and is explicitly bypassed in the peer-dead single-node path ([election.go:427](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:427)).

The cited HA-protocol mismatch precedent is only consulted by userspace/manual-transfer readiness ([daemon_ha_userspace_readiness.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_userspace_readiness.go:85)); it is not an unconditional election fence.

Lazy first-send initialization is also too late. `Manager.UpdateConfig` runs an election during bring-up before heartbeat starts ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)), while heartbeat starts later in an asynchronous retry goroutine ([daemon_ha_sync.go:767](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:767)). A preempting node may already be primary before persistence failure is discovered.

A node that has emitted—or may emit—an unpersisted epoch must be placed under an unconditional election hold before the first election. If already primary, the plan needs an explicit demotion/fencing policy. It may continue sending heartbeat while advertising fenced-secondary state; a status reason alone is insufficient.

Arithmetic remains incomplete:

- Mapping parse failure or `prev >= MaxUint64-margin` to zero can persist a lower value and incorrectly declare READY.
- `margin` and the accepted domain are undefined.
- A far-future value below that threshold remains trusted.
- Clean first boot, deleted state, unreadable state, and corrupt state are conflated.
- Exact `UnixNano` bounds are unspecified.
- Sender-counter wrap is omitted.

Finally, retrying durable I/O synchronously on every 100 ms send is unsafe. `send()` runs serially on the ticker goroutine ([heartbeat.go:708](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:708)); a slow fsync can suppress all heartbeats and repeated failures create a 10 Hz I/O/log storm. Retry needs bounded asynchronous backoff.

The claim that permanent persistence failure “degrades toward the ring bound” is false: an epoch-bearing lower frame never falls back to the v1 ring.

### 4. §5.5’s re-prime is neither unilateral nor race-free

Moving all heartbeat admission state to Manager does close the routine `RestartHeartbeat` cleartext reopen—provided `HeartbeatPeerAuthSeen` reads Manager state directly.

The recovery protocol still fails in several ways.

First, clearing `peerAuthSeen` reopens cleartext acceptance. With a local key and `peerAuthSeen=false`, the existing decision accepts a no-trailer frame ([heartbeat.go:601](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:601)). Key rotation invalidates old MACs; it does nothing to forged cleartext. An on-path injector can send an unsigned heartbeat immediately after reset and drive election without blocking the live peer. For v2→v1 rollback, v1 still emits XPFA, so clearing auth enforcement is unnecessary and actively unsafe.

Second, MAC verification is outside the proposed `m.mu` transaction ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:223)):

1. Read loop snapshots K1 and verifies an archived K1 v2 frame.
2. Config apply installs K2 and resets admission under `m.mu` ([group_state.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:85)).
3. Read loop acquires `m.mu` and commits its stale `macOK=true` result into the freshly reset state.

The old-key frame re-arms `sawEpoch/highEpoch`. Admission must carry a monotonically changing key generation and reject if it changed before commit. Admission, `lastSeen`, peer-state replacement, and election application must also be linearized relative to reset; otherwise a frame admitted just before reset can still drive election afterward.

Third, rotating only one node cannot work:

- Rolled-back A alone rotates: B retains K1 and does not reset.
- Rejecting B alone rotates: A still signs K1, so B rejects it.
- Both nodes must install the same new key.

Ordering is load-bearing. If K2 is used while A still runs v2, any K2-authenticated v2 frame can re-arm B after rollback. Reusing K1 later makes all K1 archives valid again. A safe procedure needs a never-used key and an explicit stop/isolate A → rollback A → install K2 on both nodes/reset B → reconnect sequence.

### 5. #5639 is not subsumed

The plan only moves heartbeat ownership. The sync-auth owner remains transient:

- `HeartbeatPeerAuthSeen` currently dereferences the replaceable receiver and returns false while it is nil ([peer_state.go:29](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:29)).
- Successful sync authentication arms `SessionSync.syncAuthedEver`, not Manager ([sync_auth.go:415](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:415)).
- `syncPeerAuthSeen` ORs that transient bit with the heartbeat-only provider ([sync_auth.go:139](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:139)).
- Full comms recreation replaces `SessionSync` ([daemon_ha_sync.go:851](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:851)).
- The plan nevertheless declares `sync_auth.go` unchanged ([plan.md:372](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:372)).

If sync authenticates before heartbeat, comms recreation loses the only sticky proof and the new SessionSync dual-accepts an unsigned first frame. Folding #5639 requires one Manager/daemon-scoped cross-channel auth owner armed by both heartbeat and sync. Otherwise #6169 must sequence behind an actual #5639 fix. Leaving this as Q1 is not PLAN-READY.

### 6. Locking itself is viable, but the planned transaction is not

A short pure admission operation under `m.mu` does not inherently deadlock. Status readers use `RLock`, and `StopHeartbeat` releases `m.mu` before joining goroutines ([heartbeat_manager.go:148](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:148)).

However:

- The key-generation and post-admission races above break linearizability.
- Sender key, epoch, session, and counter must be allocated from one coherent key-generation snapshot.
- §5.4 promises no durable I/O under `m.mu`, while the Appendix says `buildHeartbeat` sets BootEpoch ([plan.md:449](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:449)). Today `buildHeartbeat` holds `m.mu.RLock` while constructing the packet ([heartbeat_manager.go:263](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:263)).

The required order must be explicit: obtain a key-generation snapshot, initialize/retry the epoch outside `m.mu`, snapshot packet state, atomically allocate the nonce for that generation, then sign. A literal Appendix implementation performs durable I/O under the read lock and can self-deadlock if readiness reporting wants the write lock.

### 7. Stage 0 is useful, but not independently shippable as written

Manager-scoped sender nonce and receiver ring are worthwhile without Stage 1. They narrow routine restart churn after both sender and receiver are upgraded.

But Stage 0 currently lacks:

- coherent key-change semantics;
- the Manager-backed `HeartbeatPeerAuthSeen` accessor;
- the #5639 cross-channel owner;
- a decided cap/reject/truncate policy;
- acknowledgement that an old sender still creates new sessions on every restart during rolling deployment.

Most importantly, Stage 0 cannot establish Stage 1’s parse proof: authenticated pre-cap captures never expire. Stage 1 needs a mandatory key-rotation rollout boundary or a stronger discriminator.

### 8. New v2 flaws

The material new failures are:

- same-epoch counter reset on key rotation;
- stale old-key verification crossing the reset boundary;
- cleartext dual-accept reopened by clearing `peerAuthSeen`;
- authenticated pre-cap v1 captures falsely parsing as the exact TLV;
- synchronous persistence retry blocking heartbeat transmission;
- unauthenticated XPFA magic being trusted to choose `bodyEnd`;
- incomplete packet-effect atomicity after admission.

The lexicographic guard is the correct center of the design. The persistence/election posture, wire discriminator, shared auth owner, and coordinated key-generation protocol still require architectural revision.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
213,207
Fail. v2 fixes the ordinary heartbeat-restart case only under an unchanged key. F3, F4, and F5 remain materially open, and the key-rotation design introduces new critical races.

| Area | Result |
|---|---|
| F1 / unchanged XPFA | Resolved |
| F2 tuple guard | Correct primitive, broken lifecycle |
| F5 TLV parsing | Not resolved for archived/mixed-version frames |
| F3 persistence | Not resolved; DEGRADED is not an election fence |
| F4 lifecycle/re-prime | Routine restart fixed; recovery remains unsafe |
| Concurrency | No basic lock deadlock, but key-reset TOCTOU is critical |
| Stage 0 | Valuable, but not independently shippable as specified |

### 1. §5.2 closes routine restart churn only if the counter never resets at the same epoch

The positive result is real: if `session/counter` are created once on `Manager`, routine `RestartHeartbeat` cannot reset them. `StartHeartbeat` stops the previous sender before installing its replacement ([heartbeat_manager.go:44](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:44)), and sender shutdown joins its run loop ([heartbeat.go:742](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:742)). A full daemon reboot creates a new Manager ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)), so a new v1 session still re-anchors normally through the ring’s unseen-session branch ([heartbeat.go:574](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:574)).

But the plan then contradicts its own proof:

- §5.2 says session/counter reset on auth-key rotation ([plan §5.2](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:190)).
- The same section claims counter reset occurs only with a strictly higher daemon epoch ([plan.md:212](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:212)).
- Key rotation is in-process, so the epoch remains `E` while the counter returns to one.
- §5.5’s explicit reset set then omits session/counter entirely ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:293)).

Those are two different designs. Resetting produces repeated `(E,1...)`, so `(epoch,counter)` is no longer the claimed total order. The correct simplification is to separate local send-nonce state from receiver `peerAdmission` and never reset the Manager counter merely because the key changes. Counter exhaustion must also be defined.

A full receiver daemon restart still resets `highEpoch=0`. An archived retired frame can therefore be accepted first and drive election before the live higher epoch arrives. §5.6 acknowledges the anchor window ([plan.md:309](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:309)), but that means the framing “retired incarnation can never be replayed” and “closes daemon-reboot churn” is overstated. The live frame repairs the floor later; it does not undo election effects already triggered.

### 2. §5.1’s TLV remains ambiguous for authenticated v1 captures

The typed TLV fixes the v2-to-v2 canonical case. It does not fix rolling deployment or archived captures produced by the uncapped v1 marshaler.

A concrete MAC-valid v1 body:

- One group, three monitors, software version `dev`.
- First monitor name is 256 bytes. Its encoded length wraps to zero because the marshaler writes `uint8(len(nameBytes))` while copying the complete name ([heartbeat.go:260](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:260)).
- Choose bytes so the desynchronized parser consumes two fake 84-byte monitors and a fake 100-byte version section.
- Exactly these ten bytes remain before XPFA:

```text
01 08 01 65 03 64 65 76 01 00
```

That is syntactically `[ExtType=1][ExtLen=8][eight epoch bytes]`.

The old frame remains HMAC-valid because the unchanged MAC covers the entire malformed body ([heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)). A Stage-1 receiver treats it as epoch-bearing, bypasses the v1 ring, advances `highEpoch`, and latches `sawEpoch`; subsequent canonical v1 frames are rejected as epoch stripping under [§5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:221).

Stage 0 cannot retroactively canonicalize captures. They remain valid under the unchanged PSK forever. The design needs one of:

- a mandatory fleet-wide Stage-0 deployment followed by a never-before-used key rotation before Stage 1;
- a key-derived extension discriminator that an old sender cannot accidentally produce;
- or another wire discriminator whose validity does not depend on successfully parsing the legacy variable-length body.

The caps also need an actual policy. “Cap/reject” is not a decision when `MarshalHeartbeat` still returns no error ([plan §7](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:361)). Five RGs with 54 one-byte monitor names each yield 270 monitor records and still fit under 1472 bytes with TLV and XPFA. A 255 cap silently drops 15 accepted monitor records. Choose upstream commit rejection or deterministic truncation with rate-limited warning and telemetry.

The TLV grammar must additionally define exact consumption, duplicate epoch behavior, unknown-TLV ordering, and trailing junk. “Invalid means no epoch” is safe only after these rules and only for frames from the new canonical sender.

There is also a new keyless regression: `heartbeatAuthTrailer` recognizes XPFA using only four bytes at `len-52` ([heartbeat.go:445](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:445)). §5.3 truncates to `bodyEnd` before semantic parsing. A canonical unkeyed body can naturally place `"XPFA"` at that offset, causing the new receiver to truncate a legitimate body even though no MAC can validate the supposed trailer. Only a verified MAC may authorize `bodyEnd`; the keyless path must parse the complete legacy frame.

### 3. §5.4’s DEGRADED path is not safe; it needs an election fence

The retryable initializer is only correct if it explicitly stores `{initialized, epoch, persisted, lastError}`. The pseudocode reloads and recomputes `cand` on each invocation ([plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:251)); prose later asserts that the value is fixed once ([plan.md:273](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:273)). That invariant must exist in the state machine, not commentary.

More seriously, DEGRADED is not a safety transition:

1. A fails to persist `H` but sends it; B records `H`.
2. A reboots from stale/lost state with a regressed clock and emits `L <= H`.
3. B rejects every A heartbeat and times it out.
4. Ordinary RG readiness does not demote an existing primary ([election.go:322](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:322)) and is explicitly bypassed in the peer-dead single-node path ([election.go:427](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/election.go:427)).

The cited HA-protocol mismatch precedent is only consulted by userspace/manual-transfer readiness ([daemon_ha_userspace_readiness.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_userspace_readiness.go:85)); it is not an unconditional election fence.

Lazy first-send initialization is also too late. `Manager.UpdateConfig` runs an election during bring-up before heartbeat starts ([daemon_run_bringup.go:161](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_run_bringup.go:161)), while heartbeat starts later in an asynchronous retry goroutine ([daemon_ha_sync.go:767](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:767)). A preempting node may already be primary before persistence failure is discovered.

A node that has emitted—or may emit—an unpersisted epoch must be placed under an unconditional election hold before the first election. If already primary, the plan needs an explicit demotion/fencing policy. It may continue sending heartbeat while advertising fenced-secondary state; a status reason alone is insufficient.

Arithmetic remains incomplete:

- Mapping parse failure or `prev >= MaxUint64-margin` to zero can persist a lower value and incorrectly declare READY.
- `margin` and the accepted domain are undefined.
- A far-future value below that threshold remains trusted.
- Clean first boot, deleted state, unreadable state, and corrupt state are conflated.
- Exact `UnixNano` bounds are unspecified.
- Sender-counter wrap is omitted.

Finally, retrying durable I/O synchronously on every 100 ms send is unsafe. `send()` runs serially on the ticker goroutine ([heartbeat.go:708](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:708)); a slow fsync can suppress all heartbeats and repeated failures create a 10 Hz I/O/log storm. Retry needs bounded asynchronous backoff.

The claim that permanent persistence failure “degrades toward the ring bound” is false: an epoch-bearing lower frame never falls back to the v1 ring.

### 4. §5.5’s re-prime is neither unilateral nor race-free

Moving all heartbeat admission state to Manager does close the routine `RestartHeartbeat` cleartext reopen—provided `HeartbeatPeerAuthSeen` reads Manager state directly.

The recovery protocol still fails in several ways.

First, clearing `peerAuthSeen` reopens cleartext acceptance. With a local key and `peerAuthSeen=false`, the existing decision accepts a no-trailer frame ([heartbeat.go:601](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:601)). Key rotation invalidates old MACs; it does nothing to forged cleartext. An on-path injector can send an unsigned heartbeat immediately after reset and drive election without blocking the live peer. For v2→v1 rollback, v1 still emits XPFA, so clearing auth enforcement is unnecessary and actively unsafe.

Second, MAC verification is outside the proposed `m.mu` transaction ([plan §5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:223)):

1. Read loop snapshots K1 and verifies an archived K1 v2 frame.
2. Config apply installs K2 and resets admission under `m.mu` ([group_state.go:85](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/group_state.go:85)).
3. Read loop acquires `m.mu` and commits its stale `macOK=true` result into the freshly reset state.

The old-key frame re-arms `sawEpoch/highEpoch`. Admission must carry a monotonically changing key generation and reject if it changed before commit. Admission, `lastSeen`, peer-state replacement, and election application must also be linearized relative to reset; otherwise a frame admitted just before reset can still drive election afterward.

Third, rotating only one node cannot work:

- Rolled-back A alone rotates: B retains K1 and does not reset.
- Rejecting B alone rotates: A still signs K1, so B rejects it.
- Both nodes must install the same new key.

Ordering is load-bearing. If K2 is used while A still runs v2, any K2-authenticated v2 frame can re-arm B after rollback. Reusing K1 later makes all K1 archives valid again. A safe procedure needs a never-used key and an explicit stop/isolate A → rollback A → install K2 on both nodes/reset B → reconnect sequence.

### 5. #5639 is not subsumed

The plan only moves heartbeat ownership. The sync-auth owner remains transient:

- `HeartbeatPeerAuthSeen` currently dereferences the replaceable receiver and returns false while it is nil ([peer_state.go:29](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:29)).
- Successful sync authentication arms `SessionSync.syncAuthedEver`, not Manager ([sync_auth.go:415](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:415)).
- `syncPeerAuthSeen` ORs that transient bit with the heartbeat-only provider ([sync_auth.go:139](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_auth.go:139)).
- Full comms recreation replaces `SessionSync` ([daemon_ha_sync.go:851](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_ha_sync.go:851)).
- The plan nevertheless declares `sync_auth.go` unchanged ([plan.md:372](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:372)).

If sync authenticates before heartbeat, comms recreation loses the only sticky proof and the new SessionSync dual-accepts an unsigned first frame. Folding #5639 requires one Manager/daemon-scoped cross-channel auth owner armed by both heartbeat and sync. Otherwise #6169 must sequence behind an actual #5639 fix. Leaving this as Q1 is not PLAN-READY.

### 6. Locking itself is viable, but the planned transaction is not

A short pure admission operation under `m.mu` does not inherently deadlock. Status readers use `RLock`, and `StopHeartbeat` releases `m.mu` before joining goroutines ([heartbeat_manager.go:148](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:148)).

However:

- The key-generation and post-admission races above break linearizability.
- Sender key, epoch, session, and counter must be allocated from one coherent key-generation snapshot.
- §5.4 promises no durable I/O under `m.mu`, while the Appendix says `buildHeartbeat` sets BootEpoch ([plan.md:449](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:449)). Today `buildHeartbeat` holds `m.mu.RLock` while constructing the packet ([heartbeat_manager.go:263](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:263)).

The required order must be explicit: obtain a key-generation snapshot, initialize/retry the epoch outside `m.mu`, snapshot packet state, atomically allocate the nonce for that generation, then sign. A literal Appendix implementation performs durable I/O under the read lock and can self-deadlock if readiness reporting wants the write lock.

### 7. Stage 0 is useful, but not independently shippable as written

Manager-scoped sender nonce and receiver ring are worthwhile without Stage 1. They narrow routine restart churn after both sender and receiver are upgraded.

But Stage 0 currently lacks:

- coherent key-change semantics;
- the Manager-backed `HeartbeatPeerAuthSeen` accessor;
- the #5639 cross-channel owner;
- a decided cap/reject/truncate policy;
- acknowledgement that an old sender still creates new sessions on every restart during rolling deployment.

Most importantly, Stage 0 cannot establish Stage 1’s parse proof: authenticated pre-cap captures never expire. Stage 1 needs a mandatory key-rotation rollout boundary or a stronger discriminator.

### 8. New v2 flaws

The material new failures are:

- same-epoch counter reset on key rotation;
- stale old-key verification crossing the reset boundary;
- cleartext dual-accept reopened by clearing `peerAuthSeen`;
- authenticated pre-cap v1 captures falsely parsing as the exact TLV;
- synchronous persistence retry blocking heartbeat transmission;
- unauthenticated XPFA magic being trusted to choose `bodyEnd`;
- incomplete packet-effect atomicity after admission.

The lexicographic guard is the correct center of the design. The persistence/election posture, wire discriminator, shared auth owner, and coordinated key-generation protocol still require architectural revision.

VERDICT: PLAN-NEEDS-MAJOR
