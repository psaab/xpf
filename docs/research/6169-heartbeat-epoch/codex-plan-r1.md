Fail. Path A narrowly fixes F1, but F2, F3, and F4 remain open, while §5.1 creates a new F5-class parsing ambiguity.

| Finding | Result | Failure |
|---|---|---|
| F1 | Conditionally resolved | Unchanged XPFA is backward-compatible. |
| F2 | Not resolved — Critical | Sixty-five same-epoch sessions still churn the ring. |
| F3 | Not resolved — Critical | Persistence failure and recovery have no coherent state machine. |
| F4 | Not resolved — Critical | Only half the replay state survives restart; rollback resets the wrong node. |
| F5 | Not resolved — Major | XPFE ambiguity is gone, but residual-length inference is itself ambiguous. |

### 1. F1: Path A really does avoid the original rolling-upgrade split

For new keyed sender → origin/master keyed receiver:

1. Because XPFA remains the final 52 bytes, `heartbeatAuthTrailer` computes `start := len(data)-52` and still finds the magic exactly where expected ([heartbeat.go:445](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:445)).

2. `verifyHeartbeatMAC` authenticates every byte except the final digest ([heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)). The extra epoch body bytes are therefore covered and verify correctly.

3. `UnmarshalHeartbeat` reads HAProtocolVersion and returns without validating or consuming the remaining bytes ([heartbeat.go:361](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:361)). The only non-test caller passes the complete frame ([heartbeat.go:796](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:796)). The old receiver ignores the epoch and XPFA trailer.

For old sender → new receiver, XPFA is recognized and a canonical v1 body leaves zero residual bytes, so the new side dual-accepts while `sawEpoch=false`.

Thus [§5’s F1 argument](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:164) is correct, provided the implementation actually reserves the additional eight body bytes before monitor selection. This is the only finding the plan clears.

### 2. §5.1 residual-byte detection is not unambiguous

The proof at [§5.1 lines 192–200](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:192) assumes parsing always reaches the true end of the version section. Current encoding does not guarantee that.

`marshalHeartbeatBody` writes an arbitrary-length interface name but serializes its length as `uint8(len(nameBytes))` ([heartbeat.go:260](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:260)). A concrete MAC-valid v1 body can therefore be constructed with:

- Three monitors.
- First interface name: 256 ASCII bytes, so the serialized NameLen is zero.
- Second and third names: one byte each.
- In the first name, bytes 3 and 87 are ASCII `P` (`80`), and byte 168 is ASCII `Z` (`90`).

The receiver then:

- Treats the first real name as empty.
- Parses two fake monitors of `4+80` bytes each from that name.
- Reads fake VersionLen `90`.
- Consumes another `1+90+2` bytes for version and HA version.

From the beginning of the 256-byte name, the real v1 body has:

`256 + 5 + 5 + 3 = 269` bytes.

The parser consumes:

`84 + 84 + 1 + 90 + 2 = 261` bytes.

Exactly eight bytes remain before XPFA. The proposed receiver calls those bytes an epoch and latches `sawEpoch`, after which genuine v1 frames are rejected. Add a real eight-byte epoch to the same body and the residual becomes 16, so the genuine epoch is missed.

There is a second, more production-plausible failure. The marshaler does not cap monitor count; it writes `uint8(numMon)` ([heartbeat.go:254](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:254)). Two hundred fifty-six one-byte monitor entries fit:

`header 9 + one group 5 + count 1 + 256×5 + version 3 + epoch 8 + XPFA 52 = 1358 < 1472`.

The count wraps to zero. The receiver parses no monitors and never reaches the real epoch. If `sawEpoch` was already set before this configuration appeared, every genuine heartbeat is rejected as an epoch-strip downgrade.

Empty SoftwareVersion, a canonical 255-byte version, and normal whole-entry monitor truncation are safe. The unchecked one-byte count/length conversions destroy the universal claim.

A MAC-covered presence marker is necessary, but not sufficient while parsing can desynchronize. §5.1 must also:

- Cap/reject monitor count above 255.
- Cap/reject names above 255 bytes.
- Parse a canonical, bounded body and return its consumed offset.
- Use a typed, length-delimited extension marker rather than assigning semantic meaning to “whatever eight bytes remain.”

Otherwise F5’s trailer collision has merely been replaced with a body-boundary collision.

### 3. F2 remains bypassable at equal epoch

The assertion in [§5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:246) that equal epoch means one live session is false.

The epoch is Manager/daemon-scoped and deliberately survives heartbeat restart. But:

- `authSession` and `authCounter` are transient sender fields ([heartbeat.go:643](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:643)).
- Every `newHeartbeatSender` draws a new random session and resets its counter ([heartbeat.go:692](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:692)).
- Every `StartHeartbeat` creates a new sender and receiver ([heartbeat_manager.go:97](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:97)).
- `RestartHeartbeat` is routinely invoked after management-VRF/config rebinds ([daemon_apply_dataplane.go:429](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_apply_dataplane.go:429)).

Therefore 65 routine heartbeat restarts produce sessions S1…S65, all signed under epoch E. Every capture passes `epoch == highEpoch`, reaches `authReplay.admit`, and can churn the FIFO exactly as today ([heartbeat.go:560](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:560)). No lower-epoch mutation is needed.

Even one receiver restart is enough for a one-shot replay:

1. Receiver accepted `(E,S,c)`.
2. `RestartHeartbeat` destroys its ring but preserves Manager `highEpoch=E`.
3. Replay `(E,S,c)`.
4. Equal epoch passes; the empty ring treats S as new.

The F2 test proposed in §11 must include 65 different sessions with the same epoch. The lower-epoch-only test proves the easy case and misses the actual lifetime mismatch.

### 4. F3 persistence and recovery are not designed

[§5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:261) says both “persist before first send” and “or degrade to the wall-clock floor.” Those are mutually exclusive.

- Sending after failed persistence recreates the original self-lock risk.
- Omitting the epoch becomes an accepted downgrade before `sawEpoch`, or total rejection afterward.
- Suppressing heartbeats makes the peer time out and elect, potentially while the unsending node remains primary.
- Current `send()` returns no error and always proceeds to UDP transmission ([heartbeat.go:723](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)). “Log loudly” is not an HA state transition.

The retry claim is also incompatible with retaining `bootEpochOnce` in [§5.5](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:279) and the Appendix. Go’s `sync.Once` is consumed when its callback returns or panics; it cannot remain conditionally undone after a write failure.

“Restart the rejecting peer” is attacker-raceable. Suppose genuine A regressed to `L < H`. Restarting rejecting B clears its floor. An on-path attacker drops A’s live frame and replays an archived valid H frame first. B immediately re-anchors at H and rejects A at L forever again. In this F3 case the live peer is lower, so §5.6’s claim that a higher live frame will override the replay is specifically false.

For intact persisted state below `MaxUint64`, `persisted+1` does cover every backward wall-clock deployment. The uncovered cases are state loss/read failure and arithmetic:

- `prev == MaxUint64` wraps.
- A negative `UnixNano()` cast to uint64 produces a near-maximum poison value.
- A parseable far-future corrupted value is trusted.
- State loss plus a non-advancing snapshot clock can repeat an epoch.

The SNMP analogy is inaccurate. SNMP pins corruption and persistence failure to a ceiling and refuses authenticated traffic until recovery ([agent.go:573](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/snmp/agent.go:573)); it does not silently seed from wall clock.

F3 requires a retryable initialization state machine, an error-bearing startup boundary, checked arithmetic, bounded backoff, and a defined secondary/fencing posture before heartbeat suppression.

### 5. F4 is still open, and rollback resets the wrong node

Moving only `highEpoch/sawEpoch` leaves `authReplay` and `peerAuthSeen` on the recreated receiver ([heartbeat.go:661](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:661)). This preserves half an admission state and discards the other half.

It also leaves cleartext downgrade open. After `RestartHeartbeat`, `peerAuthSeen=false`; `heartbeatAuthDecision` accepts a missing trailer in that state ([heartbeat.go:605](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:605)). The §5.3 pseudocode invokes the epoch gate only when `auth.macOK`, so the unsigned frame bypasses `sawEpoch` entirely.

The rollback reasoning in [§5.5 lines 287–294](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:287) resets the wrong process:

- A is rolled back to v1 and restarted.
- The state rejecting A’s v1 frames lives on upgraded B.
- Restarting A does not clear B’s `sawEpoch`.
- B rejects A; old A still accepts B’s Path-A frames.
- Because HAProtocolVersion remains 1, the mismatch gate cannot fence this asymmetric interval ([peer_state.go:100](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:100)).

A one-sided rollback remains wedged and can drive asymmetric peer-dead election. Restarting both daemons merely creates a race in which an archived v2 frame can re-arm `sawEpoch` before the rolled-back peer is heard.

Option 4-ii is not sufficient as written. Persisting only highEpoch rejects lower epochs but still admits equal-epoch captures because the counter/ring and auth-mode state vanished. Persisting counters at 10 Hz is not attractive; a durable reservation/checkpoint protocol or a fresh authenticated challenge/re-prime is needed. If daemon-restart protection is part of the claimed “complete fix,” that mechanism is required now, not as a follow-up.

### 6. Concurrency is not the main failure, but the sketch is too vague

Today there is one `readLoop`, and the old receiver is joined before replacement. Under that invariant:

- One `m.mu`-protected state transition is sufficient.
- Separate atomics avoid data races but can expose a transient inconsistent `(sawEpoch, highEpoch)` status snapshot.
- There is no separate status-reader TOCTOU that requires holding a lock across the existing ring operation.

The actual atomicity failure is logical: Manager epoch state survives while receiver ring state disappears. Admission should be one operation:

`MAC verified → evaluate complete tuple → commit complete tuple`.

Advancing highEpoch before a later ring rejection is a partial commit. It usually tightens security, but it is still the wrong transaction boundary and becomes availability-sensitive during recovery or session collisions. Durable I/O must also never occur while `buildHeartbeat` holds `m.mu.RLock` ([heartbeat_manager.go:263](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:263)).

### 7. The plan defers the simpler correct design

The deferral in [§10](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:409) is not harmless scope control. It preserves the bug.

For epoch-bearing frames, use a Manager-scoped lexicographic `(epoch,counter)` guard:

- Higher epoch supersedes.
- Equal epoch requires a strictly higher counter.
- Lower epoch rejects.
- Keep the 64-session ring only for legacy v1 migration.
- Move the sender session/counter to Manager so heartbeat socket restarts do not reset them under the same epoch.

The repository already contains this comparison primitive in `fullSetSeqGuard` ([sync_conn_gen.go:64](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn_gen.go:64)). Its unrelated bulk-reprime reset semantics must not be copied.

Full receiver-daemon-restart protection then still needs a durable checkpoint/reservation or fresh challenge, plus an explicit, auditable re-prime procedure executed on the rejecting receiver under maintenance isolation or PSK rotation.

### 8. PLAN-KILL?

The threat framing is wrong: the attacker does not need 65 daemon incarnations. The ring counts sender sessions, and ordinary VRF/config heartbeat restarts generate them. That makes #6169 more credible, not less.

I would not kill the issue solely because the attacker is on-path. Replay changes packet loss into authenticated stale liveness and election-state injection. But this architecture should be killed if the project refuses the tuple/lifecycle/recovery redesign. Shipping a disk-dependent election change that still permits equal-epoch FIFO churn, cannot roll back one side safely, and has undefined persistence-failure behavior is worse than retaining the documented 64-session bound.

VERDICT: PLAN-NEEDS-MAJOR
[2mtokens used[0m
192,949
Fail. Path A narrowly fixes F1, but F2, F3, and F4 remain open, while §5.1 creates a new F5-class parsing ambiguity.

| Finding | Result | Failure |
|---|---|---|
| F1 | Conditionally resolved | Unchanged XPFA is backward-compatible. |
| F2 | Not resolved — Critical | Sixty-five same-epoch sessions still churn the ring. |
| F3 | Not resolved — Critical | Persistence failure and recovery have no coherent state machine. |
| F4 | Not resolved — Critical | Only half the replay state survives restart; rollback resets the wrong node. |
| F5 | Not resolved — Major | XPFE ambiguity is gone, but residual-length inference is itself ambiguous. |

### 1. F1: Path A really does avoid the original rolling-upgrade split

For new keyed sender → origin/master keyed receiver:

1. Because XPFA remains the final 52 bytes, `heartbeatAuthTrailer` computes `start := len(data)-52` and still finds the magic exactly where expected ([heartbeat.go:445](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:445)).

2. `verifyHeartbeatMAC` authenticates every byte except the final digest ([heartbeat.go:461](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:461)). The extra epoch body bytes are therefore covered and verify correctly.

3. `UnmarshalHeartbeat` reads HAProtocolVersion and returns without validating or consuming the remaining bytes ([heartbeat.go:361](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:361)). The only non-test caller passes the complete frame ([heartbeat.go:796](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:796)). The old receiver ignores the epoch and XPFA trailer.

For old sender → new receiver, XPFA is recognized and a canonical v1 body leaves zero residual bytes, so the new side dual-accepts while `sawEpoch=false`.

Thus [§5’s F1 argument](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:164) is correct, provided the implementation actually reserves the additional eight body bytes before monitor selection. This is the only finding the plan clears.

### 2. §5.1 residual-byte detection is not unambiguous

The proof at [§5.1 lines 192–200](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:192) assumes parsing always reaches the true end of the version section. Current encoding does not guarantee that.

`marshalHeartbeatBody` writes an arbitrary-length interface name but serializes its length as `uint8(len(nameBytes))` ([heartbeat.go:260](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:260)). A concrete MAC-valid v1 body can therefore be constructed with:

- Three monitors.
- First interface name: 256 ASCII bytes, so the serialized NameLen is zero.
- Second and third names: one byte each.
- In the first name, bytes 3 and 87 are ASCII `P` (`80`), and byte 168 is ASCII `Z` (`90`).

The receiver then:

- Treats the first real name as empty.
- Parses two fake monitors of `4+80` bytes each from that name.
- Reads fake VersionLen `90`.
- Consumes another `1+90+2` bytes for version and HA version.

From the beginning of the 256-byte name, the real v1 body has:

`256 + 5 + 5 + 3 = 269` bytes.

The parser consumes:

`84 + 84 + 1 + 90 + 2 = 261` bytes.

Exactly eight bytes remain before XPFA. The proposed receiver calls those bytes an epoch and latches `sawEpoch`, after which genuine v1 frames are rejected. Add a real eight-byte epoch to the same body and the residual becomes 16, so the genuine epoch is missed.

There is a second, more production-plausible failure. The marshaler does not cap monitor count; it writes `uint8(numMon)` ([heartbeat.go:254](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:254)). Two hundred fifty-six one-byte monitor entries fit:

`header 9 + one group 5 + count 1 + 256×5 + version 3 + epoch 8 + XPFA 52 = 1358 < 1472`.

The count wraps to zero. The receiver parses no monitors and never reaches the real epoch. If `sawEpoch` was already set before this configuration appeared, every genuine heartbeat is rejected as an epoch-strip downgrade.

Empty SoftwareVersion, a canonical 255-byte version, and normal whole-entry monitor truncation are safe. The unchecked one-byte count/length conversions destroy the universal claim.

A MAC-covered presence marker is necessary, but not sufficient while parsing can desynchronize. §5.1 must also:

- Cap/reject monitor count above 255.
- Cap/reject names above 255 bytes.
- Parse a canonical, bounded body and return its consumed offset.
- Use a typed, length-delimited extension marker rather than assigning semantic meaning to “whatever eight bytes remain.”

Otherwise F5’s trailer collision has merely been replaced with a body-boundary collision.

### 3. F2 remains bypassable at equal epoch

The assertion in [§5.3](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:246) that equal epoch means one live session is false.

The epoch is Manager/daemon-scoped and deliberately survives heartbeat restart. But:

- `authSession` and `authCounter` are transient sender fields ([heartbeat.go:643](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:643)).
- Every `newHeartbeatSender` draws a new random session and resets its counter ([heartbeat.go:692](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:692)).
- Every `StartHeartbeat` creates a new sender and receiver ([heartbeat_manager.go:97](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:97)).
- `RestartHeartbeat` is routinely invoked after management-VRF/config rebinds ([daemon_apply_dataplane.go:429](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/daemon/daemon_apply_dataplane.go:429)).

Therefore 65 routine heartbeat restarts produce sessions S1…S65, all signed under epoch E. Every capture passes `epoch == highEpoch`, reaches `authReplay.admit`, and can churn the FIFO exactly as today ([heartbeat.go:560](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:560)). No lower-epoch mutation is needed.

Even one receiver restart is enough for a one-shot replay:

1. Receiver accepted `(E,S,c)`.
2. `RestartHeartbeat` destroys its ring but preserves Manager `highEpoch=E`.
3. Replay `(E,S,c)`.
4. Equal epoch passes; the empty ring treats S as new.

The F2 test proposed in §11 must include 65 different sessions with the same epoch. The lower-epoch-only test proves the easy case and misses the actual lifetime mismatch.

### 4. F3 persistence and recovery are not designed

[§5.4](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:261) says both “persist before first send” and “or degrade to the wall-clock floor.” Those are mutually exclusive.

- Sending after failed persistence recreates the original self-lock risk.
- Omitting the epoch becomes an accepted downgrade before `sawEpoch`, or total rejection afterward.
- Suppressing heartbeats makes the peer time out and elect, potentially while the unsending node remains primary.
- Current `send()` returns no error and always proceeds to UDP transmission ([heartbeat.go:723](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:723)). “Log loudly” is not an HA state transition.

The retry claim is also incompatible with retaining `bootEpochOnce` in [§5.5](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:279) and the Appendix. Go’s `sync.Once` is consumed when its callback returns or panics; it cannot remain conditionally undone after a write failure.

“Restart the rejecting peer” is attacker-raceable. Suppose genuine A regressed to `L < H`. Restarting rejecting B clears its floor. An on-path attacker drops A’s live frame and replays an archived valid H frame first. B immediately re-anchors at H and rejects A at L forever again. In this F3 case the live peer is lower, so §5.6’s claim that a higher live frame will override the replay is specifically false.

For intact persisted state below `MaxUint64`, `persisted+1` does cover every backward wall-clock deployment. The uncovered cases are state loss/read failure and arithmetic:

- `prev == MaxUint64` wraps.
- A negative `UnixNano()` cast to uint64 produces a near-maximum poison value.
- A parseable far-future corrupted value is trusted.
- State loss plus a non-advancing snapshot clock can repeat an epoch.

The SNMP analogy is inaccurate. SNMP pins corruption and persistence failure to a ceiling and refuses authenticated traffic until recovery ([agent.go:573](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/snmp/agent.go:573)); it does not silently seed from wall clock.

F3 requires a retryable initialization state machine, an error-bearing startup boundary, checked arithmetic, bounded backoff, and a defined secondary/fencing posture before heartbeat suppression.

### 5. F4 is still open, and rollback resets the wrong node

Moving only `highEpoch/sawEpoch` leaves `authReplay` and `peerAuthSeen` on the recreated receiver ([heartbeat.go:661](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:661)). This preserves half an admission state and discards the other half.

It also leaves cleartext downgrade open. After `RestartHeartbeat`, `peerAuthSeen=false`; `heartbeatAuthDecision` accepts a missing trailer in that state ([heartbeat.go:605](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat.go:605)). The §5.3 pseudocode invokes the epoch gate only when `auth.macOK`, so the unsigned frame bypasses `sawEpoch` entirely.

The rollback reasoning in [§5.5 lines 287–294](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:287) resets the wrong process:

- A is rolled back to v1 and restarted.
- The state rejecting A’s v1 frames lives on upgraded B.
- Restarting A does not clear B’s `sawEpoch`.
- B rejects A; old A still accepts B’s Path-A frames.
- Because HAProtocolVersion remains 1, the mismatch gate cannot fence this asymmetric interval ([peer_state.go:100](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/peer_state.go:100)).

A one-sided rollback remains wedged and can drive asymmetric peer-dead election. Restarting both daemons merely creates a race in which an archived v2 frame can re-arm `sawEpoch` before the rolled-back peer is heard.

Option 4-ii is not sufficient as written. Persisting only highEpoch rejects lower epochs but still admits equal-epoch captures because the counter/ring and auth-mode state vanished. Persisting counters at 10 Hz is not attractive; a durable reservation/checkpoint protocol or a fresh authenticated challenge/re-prime is needed. If daemon-restart protection is part of the claimed “complete fix,” that mechanism is required now, not as a follow-up.

### 6. Concurrency is not the main failure, but the sketch is too vague

Today there is one `readLoop`, and the old receiver is joined before replacement. Under that invariant:

- One `m.mu`-protected state transition is sufficient.
- Separate atomics avoid data races but can expose a transient inconsistent `(sawEpoch, highEpoch)` status snapshot.
- There is no separate status-reader TOCTOU that requires holding a lock across the existing ring operation.

The actual atomicity failure is logical: Manager epoch state survives while receiver ring state disappears. Admission should be one operation:

`MAC verified → evaluate complete tuple → commit complete tuple`.

Advancing highEpoch before a later ring rejection is a partial commit. It usually tightens security, but it is still the wrong transaction boundary and becomes availability-sensitive during recovery or session collisions. Durable I/O must also never occur while `buildHeartbeat` holds `m.mu.RLock` ([heartbeat_manager.go:263](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/heartbeat_manager.go:263)).

### 7. The plan defers the simpler correct design

The deferral in [§10](/home/ps/git/bpfrx/.claude/worktrees/6169-research/docs/research/6169-heartbeat-epoch/plan.md:409) is not harmless scope control. It preserves the bug.

For epoch-bearing frames, use a Manager-scoped lexicographic `(epoch,counter)` guard:

- Higher epoch supersedes.
- Equal epoch requires a strictly higher counter.
- Lower epoch rejects.
- Keep the 64-session ring only for legacy v1 migration.
- Move the sender session/counter to Manager so heartbeat socket restarts do not reset them under the same epoch.

The repository already contains this comparison primitive in `fullSetSeqGuard` ([sync_conn_gen.go:64](/home/ps/git/bpfrx/.claude/worktrees/6169-research/pkg/cluster/sync_conn_gen.go:64)). Its unrelated bulk-reprime reset semantics must not be copied.

Full receiver-daemon-restart protection then still needs a durable checkpoint/reservation or fresh challenge, plus an explicit, auditable re-prime procedure executed on the rejecting receiver under maintenance isolation or PSK rotation.

### 8. PLAN-KILL?

The threat framing is wrong: the attacker does not need 65 daemon incarnations. The ring counts sender sessions, and ordinary VRF/config heartbeat restarts generate them. That makes #6169 more credible, not less.

I would not kill the issue solely because the attacker is on-path. Replay changes packet loss into authenticated stale liveness and election-state injection. But this architecture should be killed if the project refuses the tuple/lifecycle/recovery redesign. Shipping a disk-dependent election change that still permits equal-epoch FIFO churn, cannot roll back one side safely, and has undefined persistence-failure behavior is worse than retaining the documented 64-session bound.

VERDICT: PLAN-NEEDS-MAJOR
