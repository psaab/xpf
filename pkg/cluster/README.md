# pkg/cluster

Chassis-cluster HA state machine. Owns node state (Primary, Secondary,
SecondaryHold, Lost, Disabled), redundancy-group election, readiness
gates, manual failover, and the callbacks that fire session/config/IPsec
sync.

## Entry points

The legacy `cluster.go` (2429 LOC) was split in #1541 into sibling
files inside `package cluster`. Public API is preserved verbatim;
locating any symbol below is now a matter of opening the named file.

- `NodeState`, `RedundancyGroupState`, `ClusterEvent`,
  `RetryablePreFailoverError`, `Manager` (struct + `NewManager` +
  lifecycle: `Start`, `Stop`, `Events`, `Monitor`, `NodeID`,
  `ClusterID`, `SetOnEventDrop`, `sendEvent`) — `manager.go`.
- `electRG`, `runElection`, `electSingleNode`, `EffectivePriority`,
  `SetMonitorWeight`, `recalcWeight` — `election.go`.
- `StartHeartbeat`, `StopHeartbeat`, `RestartHeartbeat`,
  `buildHeartbeat`, `handlePeerHeartbeat`, `handlePeerTimeout`,
  `handlePeerNeverSeen`, `HeartbeatStats`,
  `vrfListenConfig` — `heartbeat_manager.go`.

  **Start/stop lifecycle tenure (#7257).** `StartHeartbeat` publishes
  `hbSender`/`hbReceiver` and *starts* them in ONE critical section, and refuses
  to publish at all if a `StopHeartbeat` overtook it while its sockets were
  being created. `Manager.hbEpoch` is the tenure counter: `StopHeartbeat` bumps
  it under `mu`; `StartHeartbeat` captures it **after** its own #4033 idempotent
  teardown (capturing at entry would compare against a value the call had itself
  invalidated) and re-checks it under the publish lock, returning
  `ErrHeartbeatStartSuperseded` if it moved. Callers must treat that sentinel as
  terminal, not as a bind failure — retrying would resurrect a heartbeat the
  teardown exists to remove; `startHeartbeatWithRetry` does.

  This is the same shape `publishSessionSyncIfCurrent` uses for the session-sync
  constructor, and for the same reason: the daemon's cluster-comms teardown
  cancels a context and joins exactly one goroutine (`clusterCommsWG`), so every
  OTHER comms-scoped goroutine that publishes shared state needs a generation
  gate of its own. The heartbeat retry loop runs on a bare `go` and is not in
  that WaitGroup.
- `HeartbeatPacket`, `MarshalHeartbeat`,
  `UnmarshalHeartbeat`, the #4107 control-channel auth
  (`MarshalHeartbeatAuth`, `marshalHeartbeatAuthEpoch`,
  `heartbeatAuthTrailer`, `verifyHeartbeatMAC`, `heartbeatAuthReplay`,
  `heartbeatAuthState.admitAuthed`, `heartbeatAuthDecision`,
  `Manager.heartbeatNonce`), sender/receiver goroutine types —
  `heartbeat.go`. See "Control-channel authentication" below.
- The #6169 across-reboot boot epoch — wire section constants, the
  key-derived marker (`heartbeatEpochMarker`), the verified-frame reader
  (`heartbeatFrameEpoch`), the plausibility bound (`epochUsableAsFloor`),
  the wall-clock seed published synchronously (`Manager.heartbeatBootEpoch`,
  increasing while the clock advances — not monotonic across a backward step,
  residual 3) with its off-path, RE-RUNNABLE persistence refinement
  (`refineBootEpoch`, `withEpochFileLock`, `Manager.refreshBootEpoch`) and the
  start-time wiring (`Manager.initHeartbeatEpochState`) — `heartbeat_epoch.go`. The downgrade
  latch itself is process-scoped state on `heartbeatAuthState`; there is no
  peer-floor file.
  - **A returned `Manager.Stop` does NOT imply the epoch flock is released
    (#6826).** `Stop` joins the refinement worker with a bounded budget
    (`bootEpochStopJoinBudget`) and, on timeout, warns and returns; nothing
    cancels the worker, and `withEpochFileLock` holds `LOCK_EX` across the
    callback's durable write and `fsync`. So a timed-out `Stop` returns while a
    lock OTHER PROCESSES can see is still held.

    It is stated rather than eliminated because both alternatives are worse.
    Releasing on the timeout path means interrupting a durable write plus
    `fsync` at an arbitrary point, which is how a torn epoch file is written.
    Making the budget cover the worst case is not possible — the worst case is a
    wedged `fsync`, and refusing to block on that is why the bound exists.

    What closes the hole is the OTHER side: `acquireEpochFileLock` waits
    `bootEpochLockAcquireBudget` for a contended lock and then DECLINES the
    persist, so an incoming process meeting an outgoing one's still-held lock
    degrades to "no backward-clock-step protection this pass" instead of parking
    behind it. That matters because restart is the documented recovery path here
    — a day-2 topology or identity change is refused at commit
    (`pkg/daemon/cluster_topology_preflight.go`) — so the incoming process is
    exactly the party positioned to meet the lock. Declining matches its
    siblings: `MkdirAllDurable` and `WriteFileDurable` failures already decline.

    Both directions are pinned:
    `TestStopReturnsWhileEpochFlockIsStillHeld6826` (Stop returns, lock held) and
    `TestIncomingProcessDeclinesRatherThanBlocking6826` (the incoming side gives
    up on time rather than blocking), with a ground-truth control asserting a
    second open file description really does contend — without which every
    lock-availability assertion would pass vacuously.
- Single-RG manual failover and transfer-commit protocol
  (`ManualFailover`, `ForceSecondary`, `ResetFailover`,
  `RequestPeerFailover`, `commitRequestedPeerFailover`,
  `abortRequestedPeerFailover`, `notePeerTransferCommitted`,
  `FinalizePeerTransferOut`, `FenceStatus`), the batch variants
  (`ManualFailoverBatch`, `RequestPeerFailoverBatch`,
  `FinalizePeerTransferOutBatch`, etc.), the owner-side
  transfer-out lease (`ArmRemoteTransferOutLease`,
  `ClearRemoteTransferOutLease`,
  `SetRemoteTransferOutLeaseDuration`,
  `clearRemoteTransferOutLeaseLocked`,
  `manualFailoverRestoreWeightLocked`; see "Owner-side
  transfer-out lease" below), and all transfer-commit
  state machine `*Locked` helpers
  (`applyPeerTransferOutOverrideLocked`,
  `clearPeerTransferOutOverrideLocked`,
  `restorePeerTransferOutOverrideLocked`,
  `transferCommitGracePeriodLocked` — sized from
  `liveHeartbeatTimingLocked`, see "Live vs desired heartbeat
  timing" below,
  `suppressPeerTimeoutForTransferCommitLocked`,
  `applyTransferCommitOverridesOnPeerStateLocked`) — `failover.go`.
  Co-locating the entire manual-failover locking domain in one
  file keeps the "committed-failover-suppresses-stale-heartbeat"
  invariant answerable by reading one file end-to-end.
- Readiness gate (`SetRGReady`) — `readiness.go`.

### `UpdateConfig` is id-keyed and last-wins (#6543)

`UpdateConfig` walks `cfg.RedundancyGroups` — a SLICE — into `m.groups`, a
`map[int]*RedundancyGroupState` keyed by `rg.ID`, doing
`existing.LocalPriority = rg.NodePriorities[m.nodeID]` on every visit. Two
compiled records sharing one id are therefore a silent overwrite by whichever
came last, and a `NodePriorities` MAP MISS is indistinguishable from a
configured priority of 0.

That was reachable from config: `redundancy-group 1 node 0 priority 200` plus
`redundancy-group 01 preempt` compiled to two `ID=1` records, one with an empty
priority map, so node 0 ran RG 1 at priority **0** instead of 200 and lost an
election it was configured to win. The fix is upstream — `compileChassis` now
folds redundancy-group instances by CANONICAL int id, so the compiler cannot
hand `UpdateConfig` two records for one group (see `docs/config-schema.md`,
"A redundancy-group is folded by CANONICAL ID"). The runtime half of that
property is pinned in `rg_id_canonical_6543_test.go`, which drives real set
lines through the real compiler into a real `Manager`.

The last-wins loop itself is unchanged and is still the contract: ONE compiled
record per redundancy-group id. A future caller that synthesizes
`ClusterConfig` records directly (peer sync, tests) owes that same invariant —
`UpdateConfig` does not enforce it.

### Live vs desired heartbeat timing (#5081)

`Manager.hbInterval` / `Manager.hbThreshold` are the **desired**
(committed) values: `UpdateConfig` rewrites them on every commit.
`StartHeartbeat` snapshots them into the sender and the receiver, and
nothing restarts the heartbeat when only the timing changes — the
restart trigger keys on endpoint fields (`clusterTransportKey`,
`pkg/daemon/daemon_ha_sync.go`), and `RestartHeartbeat` is reached only
from the VRF-rebind path. So after `set chassis cluster
heartbeat-interval` the wire keeps the old cadence and
`heartbeatReceiver.checkTimeout` keeps declaring the peer dead at the
old `threshold * interval` until something else rebuilds the heartbeat.

`liveHeartbeatTimingLocked` (`failover.go`) returns what the RUNNING
receiver is using, falling back to the desired values when no heartbeat
is running. Anything whose correctness depends on covering dead-peer
detection MUST size from it, not from `m.hbInterval` /
`m.hbThreshold` directly:

- `transferCommitGracePeriodLocked` — sizing this from the desired
  values under-runs the window whenever a commit SHORTENS the
  configured timing (desired `3 x 100ms` yields the 10s floor while the
  running receiver still declares death at `5 x 1000ms`), so the grace
  can expire before the timeout it exists to suppress and a manual
  transfer takes a spurious peer-death failover.
- `FormatInformation` (`status.go`) renders the live values and names
  the committed-but-unapplied ones on a separate
  `Heartbeat pending restart:` line; when they agree the render is
  byte-identical to pre-#5081.

Applying a committed timing change to the live heartbeat (rather than
only reporting the divergence) is the remaining half and is tracked
separately — it belongs with the control-link auth posture in the
comms restart key.
- Group-state accessors (`UpdateConfig`, `GroupStates`,
  `DataGroupIDs`, `GroupState`, `IsLocalPrimary`,
  `IsLocalPrimaryAny`, `LocalPriorities`) — `group_state.go`.
- Peer-state accessors (`PeerAlive`, `PeerNodeID`,
  `PeerGroupStates`, software/HA-protocol version,
  `PeerMonitorStatuses`) — `peer_state.go`.
- Sync state (`SetSyncReady`, `IsSyncReady`,
  `SetSyncTransport`, `SyncTransport`, `SetSyncStats`,
  `GetSyncStats`, `IsSyncConnected`) — `sync_state.go`.
- Hooks (`SetPreManualFailoverHook`,
  `SetTransferReadinessFunc`,
  `SetLocalTransferCommitReadyHook`,
  `SetPeerFailoverFunc`, `SetPeerFailoverCommitFunc`,
  `SetPeerFailoverBatchFunc`,
  `SetPeerFailoverCommitBatchFunc`, `SetPeerFenceFunc`,
  `SetPeerTimeoutGuard`) — `hooks.go`.
- Event-history methods (`RecordEvent`, `EventHistoryFor`) —
  `events_log.go`. Underlying types and `EventHistory` ring
  buffer — `events.go`.
- Status formatting (`FormatStatus`, `FormatInformation`,
  `FormatStatistics`, `FormatControlPlaneStatistics`,
  `FormatDataPlaneStatistics`, `FormatDataPlaneInterfaces`,
  `FormatIPMonitoringStatus`, `FormatInterfaces`,
  `InterfaceMonitorInfo`, `RethInfo`, `InterfacesInput`) —
  `status.go`.
  `FormatInformation` is the ONE render behind `show chassis cluster
  information` on both surfaces — the local CLI
  (`pkg/cli/cli_show_cluster.go`) and the gRPC remote CLI
  (`pkg/grpcapi/server_show_cluster_text.go`) both call it — so a section
  added there reaches both. Its "Peer fencing:" block (#72) renders
  `FenceStatus()`: the CURRENTLY configured action (`disabled` when the
  `peer-fencing` leaf is absent, which can differ from the action past
  events were recorded under) plus every `EventFence` attempt and its
  result. Under `disable-rg-confirmed` (#7147) it also renders a
  `Confirmations:` line off `SyncStats` — `timed out` there counts
  takeovers that proceeded WITHOUT the confirmation the operator asked
  for, which no other counter distinguishes. Do not confuse it with the
  "Install fence:" block above it — that one is the bulk-sync install
  barrier (`LastFenceSeq`), not the peer split-brain fence.
- `triggerGARP` (no-op/log hook today — native VRRP owns GARP),
  plus the gratuitous-ARP / unsolicited-NA burst senders — `garp.go`.
  `SendGratuitousARPBurst` / `SendGratuitousIPv6Burst` send the first
  frame synchronously (error returned to the caller) and the remaining
  follow-up frames at 50ms intervals in a background goroutine. The
  follow-up sends are the failover-convergence reliability mechanism, so
  their send errors are NOT dropped: each failed follow-up frame bumps the
  package-level `burstSendErrors` counter (exported via `BurstSendErrors()`
  for observability) and is logged at Debug; a single Warn fires after the
  burst if any frame failed. The loop never aborts on a transient SEND error
  (#2623). The burst remains non-blocking and the #2081/#2082 epoch +
  dampener storm-control gates live in `pkg/vrrp`, untouched by this.
  The follow-up loop DOES abort cleanly — before any further frame — on
  abdication: `SendGratuitousARPBurstGated` / `SendGratuitousIPv6BurstGated`
  take a `BurstStillValid func() bool` predicate, captured at burst start and
  checked before EVERY follow-up frame; `pkg/vrrp.sendGARP` passes a closure
  that returns true only while the node is still master AND `garpEpoch` is
  unchanged (#2867). When it returns false the loop stops, so a node that
  loses master (or whose burst is superseded by a newer epoch) mid-burst stops
  re-poisoning neighbor caches for VIPs it no longer owns. The original
  `SendGratuitousARPBurst` / `SendGratuitousIPv6Burst` are thin wrappers that
  pass a nil predicate (ungated, run-to-completion) for callers with no
  per-instance epoch/state to gate against (direct-mode re-announce, tests).
- `SessionSync` — `sync.go`, `sync_conn.go` (connection lifecycle:
  dial/accept/install/start/stop/disconnect), `sync_conn_gen.go` (session
  generation guards + synced-session apply), `sync_conn_read.go`
  (receive/dispatch), `sync_conn_write.go` (send/queue/delete-journal),
  `sync_conn_sweep.go` (incremental sync sweep), `sync_conn_config.go`
  (config replication), `sync_bulk.go`, `runtime.go`. HA
  session replication. After #1518, `NewSessionSync`, `NewDualSessionSync`,
  and `SetRuntime` accept the narrow `clusterRuntime` (see `runtime.go`) —
  `Sessions() dataplane.SessionStore` plus `Telemetry() dataplane.Telemetry`.
  Both the legacy `*dataplane.Manager` and the userspace
  `LegacyDataPlaneAdapter` satisfy `clusterRuntime` directly. The deprecated
  `SetDataPlane(dataplane.DataPlane)` setter is retained one release cycle
  for any out-of-tree caller and routes through the same
  `SessionStoreOf`/`TelemetryOf` adapters. The receive, sweep, bulk export,
  and stale-reconcile paths must stay on those runtime-domain interfaces.

The primary consumer of the `Manager.Events()` channel is
`pkg/daemon/daemon_ha.go`, which fans events out (HA sync, status
publish, etc.). `pkg/cluster/reth.go::HandleStateChange` is a
state-handler method, not the event-channel consumer.

## Takeover readiness gate and hold (#103)

Election gates promotion on `RedundancyGroupState.IsReadyForTakeover(holdTime)`
(`manager.go`), which is TWO conditions: `Ready` is true AND it has been true
for at least `takeoverHoldTime`. `Ready` is pushed in from the daemon reconcile
pass — `Daemon.takeoverReadinessForRG` (`pkg/daemon/daemon_ha_userspace_readiness.go`)
ANDs four inputs and calls `SetRGReady`:

| Input | Source | Not-ready when |
|-------|--------|----------------|
| interfaces | `Monitor.RGInterfaceReady` (`monitor.go`) | a LOCAL required interface is missing or down. An interface whose FPC slot maps to the peer node is skipped — it cannot exist locally. |
| VRRP | `vrrp.Manager.RGVRRPReady` | a desired RETH instance is in `unbuiltDesired` (#5641), or the RG has RETH interfaces and no instance at all. `checkNoRethTakeoverReadiness` replaces this in no-RETH-VRRP mode. |
| fabric | `d.fabricPopulated` | the fabric forwarding path is unpopulated. Forced ready when the peer is not alive. |
| userspace dataplane | `TakeoverReady()` on the published runtime | fail-closed: config says userspace but no dataplane is published. |

`SetRGReady` (`readiness.go`) stamps `ReadySince` on the not-ready -> ready edge
and arms a `holdTimer` to re-run the election when the hold expires; the
ready -> not-ready edge clears `ReadySince` and stops the timer, so a readiness
flap restarts the hold rather than accumulating credit.

**Ownership and FORWARDING are different properties too** (#7367). `FormatStatus`
renders the cluster state machine's view — priority, state, preempt, manual,
monitor-failures — and none of those terms says whether the node is actually
forwarding. That is not a cosmetic gap: `rgStateMachine.reconcileLocked`
computes `desired = clusterPri || allMasterLocked()` in non-strict mode, so
ownership and forwarding are an **OR**, not an identity, and "owns the group and
forwards nothing" is a representable state. It is the shape of the #6656
incident, which rendered as a healthy cluster on **both** nodes at once.

The per-RG `Forwarding:` sub-line closes that. The daemon supplies the
dataplane's view through `SetRGForwardingFunc` (`hooks.go`) — it owns the
`rgStateMachine`, so the value crosses the boundary rather than being read here
— and `ClassifyRGForwarding` (`rg_forwarding.go`) compares it against ownership.
Three notes on the design:

- It reports **applied** `rg_active` (`IsActive()`), not `DesiredActive()`. A
  group whose desired state is active but whose apply failed is exactly the
  divergence being surfaced; the desired value would render it healthy.
- Partial VRRP mastership is classified **before** the ownership comparison. It
  is a defect under either ownership value, so filing it by ownership would put
  one wire condition under two verdicts and hide half of them.
- An unwired hook, or a group with no state machine, **omits** the line rather
  than rendering a zero value. A default would assert "not forwarding" about a
  group whose forwarding state is merely unknown.

**The render is parsed by whole-line regexes, so line SHAPE is a contract.**
`test/incus/test-failover.sh` greps `node1.*primary` over the entire output and
does `grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"`;
`test/incus/deploy-lib.sh` awk-matches `$1 == "node0"` inside an RG block and
reads `$3` as the status. So a new line must (a) sit **after** the node rows, or
it consumes the `-A1` window, (b) lead with a non-node first field, and (c)
avoid the tokens `primary`/`secondary` anywhere. A line that can be read as a
node row steers a rolling deploy into restarting the PRIMARY first (#4009).
`TestForwardingLineIsNotParseableAsANodeRow7367` pins all three.

**`Ready` and takeover-ELIGIBLE are different properties**, and the status
render must not conflate them: inside the hold window an RG is `Ready` while
every election gate still declines to promote it. `FormatStatus` /
`FormatInformation` therefore key their "Takeover ready:" line on
`TakeoverHoldRemaining` and report `no (takeover hold: X of Y remaining)`, and
`FormatInformation` prints the configured `Takeover hold time:` line. Note
`pkg/upgrade`'s pre-demotion precheck parses the first token after
`Takeover ready:` and treats `no` as a blocker, which is the intended reading —
a holding RG genuinely cannot take over yet.

**The kernel-upgrade election hold is annotated too (#6495).** On a #1930
candidate trial boot the daemon sets `kernelUpgradeHold`, which unconditionally
holds the node SECONDARY until the promotion marker confirms the running
kernel. Until #6495 nothing rendered it, so a node parked SECONDARY by the
*expected gate* was indistinguishable from one demoted by a monitor failure or
a manual failover — during exactly the maintenance window where an operator is
deciding whether what they see is normal. `FormatStatus` and
`FormatInformation` now emit a `Held secondary: <reason>` line rendering
`Manager.KernelUpgradeHoldReason()`, the same value `show system
kernel-upgrade` reads through the daemon.

**Two reasons, not one.** The daemon sets this single flag for two materially
different conditions: a genuinely ARMED candidate
(`KernelUpgradeHoldCandidate`), and the #5682 fail-closed hold taken when
`IsArmed` returns an **error** (`KernelUpgradeHoldUnreadableJournal`). Their
remedies differ — wait for the promotion marker, versus repair `/var/lib/xpf` —
so `SetKernelUpgradeHold` requires the caller to say which, and
`KernelUpgradeHeld()` stays the yes/no predicate the *election* uses rather
than the thing the status renders. A single string would be a false statement
in the fail-closed case, where the daemon does not know a candidate exists and
no marker may ever be written.

Two properties of that line are load-bearing rather than cosmetic:

- It is **node-scoped and rendered once**, in the node header rather than
  inside the per-RG loop. The hold holds the whole node regardless of how many
  redundancy groups exist, and a node with no RGs configured yet would render
  nothing at all from inside the loop.
- It sits **above every `Redundancy group:` header** and its first field is
  `Held`, not a node token. `deploy_rolling_secondary_node`
  (`test/incus/deploy-lib.sh`) picks the RG0 secondary by awk-matching
  `$1 == "node0"` inside an RG block, and a rolling cluster deploy uses that
  answer to decide which node to restart first — a line it misread would
  restart the PRIMARY first and cause a spurious mid-deploy failover (#4009).

The hold does **not** degrade `Local node:` health. The node is healthy; it is
deliberately not eligible. Folding it into health would tell the operator
something false and send them chasing a fault that does not exist.

`DefaultTakeoverHoldTime` is **0**: with `set chassis cluster
takeover-hold-time` unset the gate is readiness-only and both renders are
byte-identical to their pre-#103 form. It shipped at 3s in `91a57cf` and was
changed to 0 in `cd4dbe9`, a bodyless commit with no recorded rationale.

Two things the gate deliberately does NOT do, both still open:

- **`electSingleNode` bypasses the gate when the peer is not alive**
  (`election.go`) — a lone node promotes on `Weight > 0` regardless of
  readiness. This is fail-open on purpose: a survivor that refuses to take over
  is a total outage. It does mean #103's "peer-loss event does not force
  takeover when readiness is false" is not satisfied, and a cold boot with no
  peer ever seen promotes an RG whose interfaces are still missing.
- **Session-sync readiness is not an input** to the gate — that is #110.

## Peer-liveness cold-boot grace (#4386)

`heartbeatReceiver.checkTimeout` (`heartbeat.go`) makes both peer-liveness
decisions, and both are gated behind a single cold-boot floor,
`heartbeatStartupGrace` (30s). For that window after a receiver starts, the
local config apply phase — VRF binding, FRR reload, fabric creation, RETH MAC
down/up — can disrupt the control-link UDP receive path for 10-15+ seconds:

- **Seen-then-lost** (`lastSeen != 0`): peer-lost is suppressed entirely inside
  the grace, so a recovering node does not declare a still-live peer dead on
  the first dropped heartbeat. After the grace, staleness (`heartbeatStale`,
  `threshold*interval`) drives `handlePeerTimeout`.
- **Never-seen-at-boot** (`lastSeen == 0`): single-node promotion is held
  behind the SAME floor via `neverSeenConfirmed(sinceStart, grace)`. Deciding a
  peer NEVER EXISTED is different from a peer that WAS seen then went silent —
  on a **simultaneous cold boot** the first heartbeats from a live peer are
  dropped and `lastSeen` stays 0 on BOTH nodes. Promoting at
  `threshold*interval` (~500ms) would then make BOTH claim primary and the RETH
  virtual MAC — a 10-15s split-brain until the link recovers and dual-active
  resolution demotes one. The floor lets a slow-to-appear peer be heard first.

The floor DELAYS the never-seen decision; it never blocks it. A genuinely
absent peer — a single-node deployment, or a peer that will never come up —
still promotes once the grace elapses (`neverSeenConfirmed` returns true at
`sinceStart >= grace`), so there is no permanent no-master. `handlePeerNeverSeen`
sets `peerEverSeen` and runs `electSingleNode`; `election.go` bypasses the
readiness gate when `!peerAlive`, so the surviving node takes over.

## Duplicate node-id (invalid cluster, #4549 F11)

Two chassis sharing a node-id is an invalid cluster: the HA protocol
carries no per-node identity besides the node-id, so election has **no
asymmetric discriminator** to elect a single primary — both nodes run the
identical `electRG` code and compute the identical result. There is no
correct runtime resolution; the only remedy is correcting
`/etc/xpf/node-id` on one chassis.

Two defenses, both fail-safe rather than manufacturing a false winner:

- **Join point (`heartbeatReceiver.recvLoop`, `heartbeat.go`).** On a
  unicast point-to-point control link a node never receives its own
  frame, so a same-cluster heartbeat carrying the local node-id is a
  duplicate-node-id peer, not a loopback. The receiver still discards it
  (it cannot be told apart from a stray loopback, and a duplicate-node-id
  cluster is unresolvable), but calls `NoteDuplicateNodeIDHeartbeat` to
  emit a rate-limited (`>=30s`) `slog.Error` so the operator sees the
  misconfiguration instead of a silent split-brain. Because the frame is
  discarded, `peerAlive`/`peerNodeID` never reflect the duplicate peer, so
  in production both nodes run `electSingleNode` and would otherwise both
  claim PRIMARY — the warning is the operator-facing signal that this is
  happening.

- **Election tie-break (`electRG`, `election.go`).** If a same-node-id
  peer ever does reach election (the direct API / tests, or any future
  path that does not go through `recvLoop`), the dual-active tie, the
  preempt tie, and the initial-state tie all detect
  `m.nodeID == m.peerNodeID` and **fail closed to SECONDARY** (via
  `warnDuplicateNodeIDLocked`). Before the fix the dual-active and preempt
  ties returned "winner stays"/"no change", leaving both symmetric nodes
  PRIMARY (a permanent dual-primary split-brain — duplicate VIP / ARP
  conflict). Yielding both nodes to SECONDARY produces a clean, obvious,
  loudly-logged outage instead of subtle duplicate-address corruption.

## Session-sync fail-closed authentication (#5078)

The session-sync TCP stream (`sync_auth.go`) authenticates with the SAME
control-link PSK. Until #5078, a node that HAD a key still **dual-accepted** an
unkeyed or legacy peer on first contact: `syncAuthDecision` granted a grace
whenever the sticky downgrade guard (`peerAuthSeen`) had not yet armed.

That grace was not a compatibility affordance, it was an unauthenticated
**active** bypass, and it did not depend on the reflection weakness this issue
also tracks:

- the window is open on **every fresh boot** — "before the guard arms" is
  exactly when a node starts;
- an admitted peer's first frame was executed **before** the connection was
  installed (`handleNewConnection`), and `syncMsgFence` on that path reaches
  `OnFenceReceived`, which disables every routing group;
- the admitted connection then **displaces** the legitimate peer's connection,
  and arming the guard later does not evict it.

So a PSK-less host reaching the fabric could fence the node and hold the peer
slot. Two changes close it:

- **A keyed node requires an authenticated peer.** `syncAuthDecision` no longer
  consults `peerAuthSeen` for the unkeyed-peer branch — it cannot, since the
  whole exposure is the pre-arm window. An unkeyed/legacy peer is rejected.
- **The pre-admission frame mechanism is DELETED, not reordered.** A legacy
  peer's first frame used to be carried out of the handshake as a
  `pendingFrame` and executed BEFORE `installConn` — `syncMsgFence` on that
  path reaches `OnFenceReceived` and disables every routing group, for a peer
  that had proven nothing. Its only producer sat behind the dual-accept grace,
  so once that grace is gone the arm can never accept and the mechanism is
  unreachable. It is removed rather than left dormant: unreachable code that
  mutates cluster state before admission is one edit away from being live
  again. There is now no path by which an unadmitted connection executes
  anything.

### Session-sync authentication is Noise_NNpsk0 (#7163, closing #5078)

Both session-sync admission paths — the connection-setup handshake
(`performSyncHandshake`) and the #6628 in-place upgrade of an established
connection (`sync_auth_upgrade.go`) — run **Noise_NNpsk0** from
`github.com/flynn/noise`, keyed by the control-link PSK.

**What it replaced, and why nothing smaller would do.** The old proof was
`syncAuthProof(key, challenge)` = `HMAC(key, tag ‖ challenge)`: no
initiator/responder role, no node or endpoint identity, no transcript. The
frame key came from `syncDeriveFrameKey`, which sorted the two nonces
canonically, so BOTH directions derived one key and `wrapSyncConn` wrote those
same bytes into `readKey` and `writeKey`. Two consequences:

- **The two-connection oracle (vector B).** An attacker with no PSK opens a
  second keyed connection and relays a proof computed over connection α's nonce
  onto connection β. The nonces differ per connection, so the equal-nonce
  rejection never fired. Both nodes share ONE PSK, so the oracle can be the PEER
  NODE ITSELF, which no per-node nonce bookkeeping can observe.
- **Self-fencing.** Because `readKey == writeKey`, a frame the victim SENT
  verifies when echoed straight back on the same connection, and the anti-replay
  counter cannot see it (`verifyFrame` compares against that connection's
  RECEIVE counter, independent of its send counter). The worst reflectable frame
  is `syncMsgFence`: empty payload, and on receipt the victim disables all of
  its own redundancy groups.

Composing this in-house produced three separate findings — #5078 (reflection),
#7152 (equal-nonce) and this one. Role binding, identity binding and transcript
binding are what a standard construction supplies BY DEFINITION, and they are
exactly the three the old proof omitted. This is the appliance's first
third-party crypto dependency, accepted deliberately.

**Where each binding comes from**, so the claim can be checked rather than
taken:

- **Role** — initiator and responder are structural in the pattern. On the
  connect handshake the TCP *dialer* is the initiator; on the in-place upgrade
  the *lower node id* is. Neither is a field the peer can assert.
- **Transcript** — the handshake hash covers every message AND the prologue.
- **Identity** — protocol version, a PHASE byte (connect vs in-place upgrade),
  cluster id, ROLE-ORDERED node ids and the fabric index go in the prologue, so
  they are inside that hash. Two ends that disagree on any of them derive
  different keys and the handshake fails.
- **Direction** — `Split()` returns two CipherStates, one per direction. This is
  the specific replacement for the canonical nonce sort, and
  `TestInPlaceUpgradeInstallsDirectionalKeys7163` asserts the consequence that
  mattered: a node's own sealed fence, echoed back at it, is REFUSED.

**Why psk0 and not a static-key pattern.** The existing trust model is a
config-derived shared PSK with no static-keypair infrastructure, no CA, no
certificate lifecycle and no trust-anchor distribution. A psk0-family pattern
authenticates from that PSK directly; introducing static keys would import
exactly the lifecycle question that ruled out TLS, and it does not become free
by being called Noise.

**The PSK is DERIVED, not passed through.** Noise mandates a 256-bit preshared
key and `ControlLinkAuthKey` is an operator-authored string of arbitrary length,
so `syncNoisePSK` derives 32 bytes with a labelled SHA-256. Not truncation
(which collapses two keys sharing a 32-byte prefix) and not zero-padding (which
leaves most of the PSK constant). The label keeps this derivation from colliding
with any other use of the same config secret — the heartbeat authenticates off
it too.

**This is a FLAG DAY.** A pre-#7163 peer sends the old HELLO, which is not a
valid Noise message, so the handshake fails and the connection drops.
`SessionSyncWireVersion` is bumped 1 → 2 so `GateMixedBaseSwap` refuses a
mixed-base swap up front instead of letting an operator discover it as a fabric
that will not come up. `CurrentHAProtocolVersion` is deliberately NOT bumped:
that would additionally refuse the peer over heartbeat/failover semantics this
change does not touch (#7925 split the two counters precisely so a session-wire
change stops dragging the HA protocol out from under its own compat floor).
Sessions drop on upgrade; both nodes must be on the new build.

### Rollout: a secondary whose gate is ARMED cannot be keyed locally

Three earlier revisions of this document got this wrong in three directions —
first claiming an unavoidable deadlock, then claiming the operator can simply
"commit the key locally on each node", then claiming the gate covers every entry
point unconditionally. The mechanism, stated with its precondition:

- `applyRG0OwnershipTransition` calls `store.SetClusterReadOnly(true)` on
  `StateSecondary` / `StateSecondaryHold` (`pkg/daemon/daemon_ha.go`). It is
  driven by an RG0 **transition event** and by nothing else — there is no
  startup arming and no reconcile that re-derives the flag.
- Once armed, `EnterConfigureSession` returns `ErrClusterReadOnly` before doing
  anything else (`pkg/configstore/store_lock.go`), whichever entry point the
  operator used.

So on a secondary whose gate is armed, config mode cannot be opened at all —
this is not "the local commit gets overwritten by sync", and **config-sync is
that node's only writer** (`TestClusterReadOnly_SyncApplyBypassesGate` pins that
the HA-sync ingress path bypasses the gate).

**But arming is not universal, so do not read the heading as unconditional.** A
node that cold-starts, seats as RG0 secondary and never transitions never
reaches that call, and `Store.clusterReadOnly` starts false — so its store is
writable. REST enters a configure session with no RG0 check of its own
(`pkg/api/config.go`), where gRPC guards on `IsLocalPrimary(0)` and the
interactive CLI has its own check. That gap is **#6890**; the dropped-event
variant is **#6889**. Both are OPEN and neither is scheduled — do not read a
fix date into this sentence. The design intent is what this
section describes; treat the gap as a bug to avoid, never as a rollout
procedure.

**Performable procedures:**

1. **At provisioning / console, before the cluster forms.** `clusterReadOnly`
   zero-values to `false`, so each node can be keyed independently before it
   ever seats as secondary. This is the recommended path.
2. **On a live cluster: commit on the PRIMARY while sync is connected.** The
   established connection carries the key to the secondary. This works only
   because committing the key does not restart cluster comms — the auth key is
   deliberately absent from `clusterTransportKey`, pinned by
   `TestAuthKeyChangeDoesNotRestartClusterComms_5078`. Do not add it there; see
   that test for why it would deadlock with no self-recovery. ("Deadlock", not
   "permanent deadlock" — an operator can still break it out of band, by the
   controlled promotion in row 3 or, on a node whose gate was never armed, by
   the #6890 hole. What the hypothetical destroys is the cluster's ability to
   converge on its own.) The step-20 decision
   that must not fire on a key change is pinned separately by
   `TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078` — the struct test alone
   does not cover the call site.

   **Procedure 2 carries the risk it is trying to avoid.** The key reaches the
   secondary asynchronously, so if the session-sync connection drops in the
   window between the primary committing and the secondary applying, you land in
   exactly the keyed-primary / unkeyed-secondary state below — the now-keyed
   primary rejects the unkeyed peer's reconnect, and the key can never be
   delivered. Prefer procedure 1. If you must use procedure 2, confirm sync is
   connected immediately before committing (`show chassis cluster status`) and
   verify the secondary applied the key immediately after; treat a drop in that
   window as requiring the recovery below.

**Recovery: no path is unconditional, and the one you can plan around costs a
controlled outage.** Three earlier revisions of this section got this wrong in
three different directions — one proposed a primary-only rekey and labelled it
UNVERIFIED, the next said no recovery existed at all, the third said exactly one
path works. Each replaced a hedge with an absolute and each was refuted. So the
three candidate paths are stated individually, with their preconditions, rather
than summarised into a verdict:

1. **Primary-only rekey — CLOSED.** "Remove the key on the primary, let the peer
   reconnect unkeyed, config-sync pushes, re-add the key" cannot start: an
   unkeyed `chassis cluster` is what the commit gate rejects, so `delete chassis
   cluster authentication-key; commit` is refused by
   `validateClusterAuthKeyStrict`. This document says the same thing under "Do
   not try to return to dual-accept by clearing the key first". Tracked as
   **#6630**.
2. **Console on the seated secondary — CLOSED.** The gate is on the **config
   store**, not the transport, so `EnterConfigureSession` returns
   `ErrClusterReadOnly` regardless of which entry point the operator used —
   console, remote CLI, gRPC or REST.

   **This row used to be conditional on the gate being ARMED, and it no longer
   is (#6889/#6890).** `SetClusterReadOnly` was reached only from the RG0
   **transition** handler, so a node that cold-started, seated as secondary and
   never transitioned kept a **writable** store — and `pkg/api/config.go` enters
   a configure session with no RG0 check of its own, where the interactive CLI
   and gRPC each have one, so REST was a way in on a node that did not own
   config. The gate is now **re-derived from RG0's authoritative state** on every
   `reconcileRGState` pass (2 s, plus the event-drop nudge), so arming no longer
   depends on an edge ever being crossed. Both the never-transitioned case
   (**#6890**) and the dropped-event case (**#6889**) are closed by that one
   change: a gate derived from state cannot preserve a hole that existed only
   because the transition edge was never taken.

   What is still true: the gate reflects RG0 state within one reconcile pass,
   not instantaneously. A check made in the ~2 s after a state change may still
   observe the previous value.
3. **Controlled RG0 promotion — the only path you can PLAN for, and it is
   CONDITIONAL.** ("Plan for", not "that works": row 2 is open on an unarmed
   node, so a path exists there too — it is just a bug you must not build a
   procedure on.) Stop `xpfd` on the keyed primary; *if* the secondary wins the
   election, `applyRG0OwnershipTransition(StatePrimary)` calls
   `d.store.SetClusterReadOnly(false)` and the now-primary node accepts a local
   commit of the same key. Restart the old primary and the pair converges keyed.
   Same stop-one-node shape documented above for `configuration-synchronize`.

   **This row had TWO preconditions; #6889 removed one of them.**
   - **STILL A PRECONDITION** — the secondary must be eligible. `election.go`
     returns early on `m.kernelUpgradeHold`, and promotes only when
     `rg.Weight > 0`. Zero weight or an active upgrade hold and no promotion
     happens at all. Nothing in #6889 changes this.
   - **NO LONGER A PRECONDITION** — the promotion event no longer has to be
     delivered. `Manager.sendEvent` is still non-blocking and still drops on a
     full channel, so the *event* remains unreliable; what changed is that the
     gate is no longer driven by it. `reconcileRGState` re-derives
     `Store.ClusterReadOnly` from RG0's authoritative state and, on a
     divergence, re-drives `applyRG0OwnershipTransition` itself — so a dropped
     promotion self-heals within one reconcile pass instead of stranding the
     node until the next transition. Tracked and closed as **#6889**.

   (The unarmed-gate case from row 2 — **#6890** — was never a precondition
   here, and is now closed by the same change. It did not block promotion; it
   meant the gate you were trying to clear had never been closed on that node.)

   So this row is now the one you can plan around, with one precondition left
   rather than two. It is still **not unconditional**: an ineligible secondary
   does not promote, and no amount of reconciliation creates a primary out of a
   node with zero weight or an active upgrade hold.

So the recovery you can actually plan for is a deliberate cluster failover —
you have turned a config commit into an outage. (The row-2 unarmed-gate escape
hatch is gone as of #6890: a seated secondary's store is now gated whether or
not it ever transitioned. That removes a hazard rather than a capability — this
document already said it was "a bug you must not build a procedure on" — and in
exchange row 3 lost its event-delivery precondition, so the path you plan around
is now reliable rather than merely likely.) That is why committing
`authentication-key` must never restart cluster comms: the fallback is
CONDITIONAL on everything row 3 lists, and even when available it is one you
would have to schedule. Do not read "a fallback exists" off this sentence —
that is exactly the absolute this section keeps regrowing.
`TestAuthKeyChangeDoesNotRestartClusterComms_5078` and
`TestKeyCommitDoesNotRestartCommsAtTheCallSite_5078` pin the no-restart
behaviour; if either reds, the change under your hand is the one that forces
that outage.

## Heartbeat source pin (#6888)

The read loop discarded the UDP source address (`n, _, err := ReadFromUDP`), so
nothing compared it to the configured control-link peer. It now drops any
datagram from another source **before** unmarshal, cluster-id validation and MAC
verification.

**This is not an authentication boundary, and must not be described as one.**
Heartbeat frames are HMAC-verified in `admitFrame`, and an attacker without the
control-link PSK could never get one admitted whatever source address it
carried. What the pin adds is three narrower things:

- **Cheapest-point filtering.** An off-path sender that can reach the port
  otherwise makes the node do HMAC work on every forged frame, on a path running
  at a 200 ms interval with a threshold of 5.
- **Visibility of a misconfiguration that was previously silent.** A third node
  accidentally pointed at this control link had its frames read, MAC-checked and
  dropped with no signal anywhere. Rejections are now counted
  (`HeartbeatStats.ForeignSrcDropped`) and logged rate-limited at 30 s — a
  rejection that is not counted would reproduce the exact invisibility the pin
  exists to fix.
- **Partial constraint under a leaked PSK**, which still bounds where forged
  frames can originate.

**It compares the IP ONLY, and that is measured rather than assumed.** The
peer's *sender* socket is bound with port 0 (`net.JoinHostPort(localAddr, "0")`
in `startHeartbeatLocked`), so it sources from an **ephemeral** port unrelated
to the port it listens on, which changes on every daemon restart. Observed on
the live loss cluster:

| node | listens on | sources from |
|---|---|---|
| fw0 | `10.99.12.1:4784` | `10.99.12.1:40745` |
| fw1 | `10.99.12.2:4784` | `10.99.12.2:50923` |

A pin on the full `UDPAddr` would therefore reject **100% of legitimate
heartbeats** and take down every cluster on upgrade — strictly worse than no
pin. `TestPeerPinIgnoresPortEntirely6888` exists to say so at review time rather
than at failover time, and the admitted-peer fixture deliberately uses a port
that differs from the configured one so it could not pass under an address+port
comparison.

The zone on a link-local address is not compared either (`net.IP.Equal` ignores
it): a peer legitimately sourcing from a link-local address on the control
interface must not be rejected over a zone string. Tolerance costs little here
because the frame still faces MAC verification; strictness costs availability.

**Unset fails OPEN.** A receiver with no configured peer (nil `peerAddr`, or a
nil source address from the read) accepts every source exactly as before #6888.
A pin that rejects when it does not know what to accept converts a
defence-in-depth gap into a comms outage. `newHeartbeatReceiver` takes the
address as a **required parameter** rather than offering a setter, so the
compiler proves every construction site decided what to pass — a pin that
silently never receives its address is indistinguishable from no pin, and would
be found by an attacker or a misconfiguration rather than by review.

## Control-channel authentication (#4107, PR-A)

The cluster heartbeat drives election: `handlePeerHeartbeat` rebuilds
peer redundancy-group state directly from the packet and runs
`runElection()`, so a forged cleartext heartbeat can force the local
node PRIMARY or demote the peer (Weight=0 → local claims PRIMARY;
higher priority → local forced SECONDARY). The heartbeat is UDP on the
shared control VLAN, so any host that can reach the peer's control IP
could inject one.

**Fix (first authed channel).** When a shared PSK is configured
(`set chassis cluster authentication-key <key>` → `config.Secret`
`ClusterConfig.ControlLinkAuthKey`, plumbed into the `Manager` by
`UpdateConfig` and read via `controlLinkAuthKey()`), the sender appends
an HMAC-SHA256 auth trailer to the heartbeat frame and the receiver
rejects a forged/tampered/replayed heartbeat **before** it can refresh
peer liveness (`lastSeen`) or drive election.

- **Wire.** `MarshalHeartbeatAuth` appends a fixed 52-byte trailer
  AFTER the optional version trailer: `magic "XPFA"(4) + session(8) +
  counter(8) + HMAC-SHA256(32)`. The HMAC covers the whole frame plus
  the magic/session/counter (everything but the digest). Because
  `UnmarshalHeartbeat` already ignores bytes past the version section,
  a signed frame stays wire-parseable by a legacy / not-yet-keyed peer
  — the same additive-trailer discipline as the version trailer.
  **Never-unsigned-when-keyed invariant:** `MarshalHeartbeatAuth`
  reserves the 52-byte trailer up front via
  `marshalHeartbeatBody(pkt, heartbeatAuthTrailerSize)`, which truncates
  the best-effort monitor section (never the election-critical header /
  RG groups) to make room. So once a key is configured a heartbeat is
  ALWAYS signed — never silently downgraded to unsigned, which an
  enforcing peer would reject and split the cluster (dual-primary). The
  overflow guard is unreachable at the uint8-bounded RG count and fails
  LOUD (`slog.Error`) rather than emitting cleartext.
- **Wire, boot-epoch section (#6169).** A signed frame optionally carries
  a 16-byte boot-epoch section `marker(8) + epoch(8, little-endian)`
  inserted **BETWEEN the body and the `XPFA` trailer**
  (`marshalHeartbeatAuthEpoch`):

  ```
  [ body … version section ][ marker(8) ][ epoch(8) ][ XPFA(4) session(8) counter(8) HMAC(32) ]
                             \___ #6169 epoch section ___/\_________ #4107 auth trailer _________/
                                                          \_ signed span ends before the digest _/
  ```

  The placement is load-bearing and is **not** interchangeable with
  appending after the trailer. Appending after it (the earlier attempt,
  #6370) moves the `XPFA` magic off `len-52`, so a pre-#6169 receiver reads
  the frame as UNSIGNED — and an enforcing pre-#6169 peer then rejects
  every frame, splitting a keyed cluster mid-upgrade. With the section
  before the trailer, a pre-#6169 receiver still locates the trailer at
  `len-52`, still verifies the MAC over exactly the bytes the new sender
  signed, still decodes an identical packet (the epoch lands past the
  version section, which `UnmarshalHeartbeat` ignores), and simply never
  sees the epoch. Bidirectional compatibility with **no**
  `CurrentHAProtocolVersion` bump.

  `marker = HMAC(PSK, "xpf-ha-boot-epoch-v1")[:8]` is key-derived, NOT a
  fixed ASCII magic. The section is read at a SINGLE FIXED OFFSET back from
  the fixed-size trailer (`len-68` — one index, no search loop), so the bytes
  it lands on are the tail of the version section — a stable, build-specific
  string. A fixed magic could therefore
  be matched by an ordinary body on **every** frame of some build,
  deterministically; and because the receiver LATCHES the high-water epoch,
  a body-derived value read as a uint64 (~7e18, far above a wall-clock
  epoch ~1.8e18) would permanently lock the peer out. A key-derived marker
  is a PRF value no attacker can compute without the PSK, and an archived
  legacy body collides at only ~2⁻⁶⁴. The epoch is read **only** from a
  MAC-verified frame — only a verified frame authorises treating `len-52`
  as the end of the signed body. The tail reserve grows to 68 bytes when a
  marker is emitted, so a maximal frame still fits `maxHeartbeatSize`;
  reserving only 52 lets the frame overrun the receiver's read buffer,
  which truncates it and destroys the MAC.
- **Anti-replay.** `session` is a random per-sender-process id and
  `counter` a monotonic per-session counter. `heartbeatAuthReplay.admit`
  remembers a BOUNDED SET of per-session high-water counters
  (`heartbeatReplaySessions` slots, FIFO eviction). It accepts a strictly
  increasing counter within any KNOWN session and accepts a genuinely
  NEW, never-seen session id, so a sender restart/reboot (a routine HA
  event — `make test-failover` reboots a node) is never mistaken for a
  replay. Intra-session replays are rejected.
  **Retired-session replays are rejected (#5477).** The pre-#5477 tracker
  held exactly ONE `(session, counter)` and RE-ANCHORED on ANY session
  change, so an on-link attacker who recorded authenticated frames from
  two sessions A and B could alternate A→B→A→B indefinitely — each
  switch reset the single watermark and re-admitted the SAME recorded A
  frames, refreshing peer liveness and applying their stale role/priority
  before `handlePeerHeartbeat`. HMAC blocks forging a NEW session but not
  replaying an already-valid byte sequence. Remembering each retired
  session's watermark rejects the return to A (its counter cannot exceed
  the highest the genuine peer ever signed). Session ids are RANDOM
  (unordered), so a strictly-newer test like `fullSetSeqGuard` cannot be
  used — a bounded per-session watermark is the mechanism that separates a
  real reboot (new id) from a replay of a retired session (known id,
  no counter advance). **Bound safety and its honest limit:** the ring
  RAISES the on-link replay attacker's cost — from 2 recorded sessions
  (the pre-#5477 A→B→A loop) to `heartbeatReplaySessions`+1 — but is NOT an
  absolute bar. Eviction is FIFO and is triggered by ANY never-seen session,
  INCLUDING a REPLAYED old frame whose session is not currently in the ring:
  admit() treats it as never-seen, re-records it, and evicts the oldest.
  FIFO always leaves exactly one just-evicted session to replay back in as
  never-seen, so an attacker who captured `heartbeatReplaySessions`+1 (= 65)
  or more distinct sessions can churn the ring by REPLAY ALONE (no
  reboot, no minting) and SUSTAIN the replay indefinitely; with fewer than
  65 recordings every retired-session replay is rejected.
  **The unit is a peer DAEMON INCARNATION — but only since #6169 Stage 0.**
  A session id used to be minted per `heartbeatSender`, so every peer heartbeat
  restart (VRF rebind, HA comms restart) minted a fresh one with no reboot
  involved: the 65 above was 65 recorded heartbeat *sessions*, cheaper to
  harvest than 65 daemon incarnations, routine peer restarts consumed ring
  slots permanently once the ring outlived a local restart, and — worst — those
  extra sessions all shared ONE boot epoch, which the floor cannot separate, so
  the ring stayed churnable *within* an incarnation even under the epoch gate.
  `Manager.heartbeatNonce` now draws the session once per `Manager` and only
  advances the counter (`TestHeartbeatNonceIsIncarnationScoped_6169`), so a
  restart no longer re-anchors and the 65 really is 65 peer boots. The map
  still causes NO
  genuine-peer lockout (an evicted live watermark just makes the peer's next
  frame never-seen → admitted) and cannot grow memory (fixed 64 slots).
  **#6169 closes the ≥65 churn** with the signed boot epoch below; the ring
  is retained and still owns within-incarnation replay and the whole legacy
  (epoch-less) path.
- **Across-incarnation anti-replay — the signed boot epoch (#6169).**
  The ring can only ever be a bounded set because session ids are random and
  unordered. The frame therefore carries a **boot epoch**: a per-daemon-
  incarnation counter that increases across restarts and reboots, giving the
  receiver an order over peer incarnations in O(1) state. It is **not strictly
  increasing in every case** — the persisted term of the seed is bounded, so a
  backward clock step larger than `bootEpochMaxSkew` regresses it even with the
  file intact (residual 3, #6711).
  - **Receiver** (`heartbeatAuthState.admitAuthed`, floor `highEpoch` on the
    `Manager` so it survives a heartbeat restart exactly like the ring):
    `epoch < highEpoch` → REJECT (an incarnation OLDER than the highest one
    accepted — which is a retired one only while the sender's epoch has not
    regressed; see residual 3); `epoch == highEpoch` → fall through to the
    ring, but only for a BOUNDED SET of sessions at that value
    (`highEpochSessions`, `heartbeatEpochSessionsPerEpoch` slots);
    `epoch > highEpoch` → let the ring vet the nonce, then raise the floor and
    rebind it to that session.
    **The floor admits at most `heartbeatEpochSessionsPerEpoch` (2) SESSIONS
    PER EPOCH VALUE**, and bounding that is what makes it bound the ring
    rather than merely order it. Equality must fall through for a bound
    session — a live peer signs every frame of its incarnation with one
    epoch, so refusing equality outright declares a healthy peer dead — and
    must not fall through unbounded, because distinct sessions sharing one
    epoch churn the ring exactly as epochless frames do (measured 1625/1625
    before the binding existed; `epoch == highEpoch` used to fall through
    unconditionally). A refused frame is counted as `EpochSessionCollision`
    and rendered by `show chassis cluster status` as "Epoch session
    collisions".

    **The bound cannot be ONE, and an earlier revision of this document said
    the cost of making it one was "durable only when the clock is frozen AND
    the store never completes".** That is false. `refineBootEpoch` chains to
    `persisted+1`, which is a pure function of the FILE, so a store that
    READS but cannot WRITE — a full or read-only `/var`, with the state file
    holding a value ahead of `now` but inside `bootEpochMaxSkew` after an RTC
    ran fast and NTP corrected it back — hands EVERY successive incarnation
    the identical epoch, on a healthy advancing clock. Refinement is the
    equal-epoch generator there, not the escape from one. With a singleton
    bound the successor incarnation was refused on every heartbeat (measured
    0/40 through `initHeartbeatEpochState` over a write-failing directory),
    which at the shipped 200 ms interval and threshold 5 declares a healthy
    node dead in 1 s and takes its RGs over while it still holds them.

    **What it still costs**, stated as the bound is: a successor beyond the
    second at ONE unchanged epoch value is refused, and refused for its whole
    process lifetime, because `bootEpoch` is set once and re-refinement lands
    on the same `prev+1`. So the honest statement is *durable across every
    restart in a window up to `bootEpochMaxSkew` whenever the persist half
    cannot advance the file*, and the bound buys one restart inside that
    window rather than removing it, and it buys NONE at all against an on-link
    replay attacker: every prior incarnation's frames carry the current floor
    value under a distinct session in this regime, so one replayed archived
    frame fills the second slot and the first genuine successor is refused.
    Raising the bound does not help — an attacker spends `k-1` slots as cheaply
    as one. **Sender-side recovery** needs the wall clock to climb past
    `prev+1` **and** another restart — at most an hour.
    **Receiver-side, only a full `xpfd` restart on the receiving node clears
    it**, and an earlier revision of this document had the reason exactly
    backwards. `highEpoch` and `highEpochSessions` live on the `Manager`, which
    is why a *heartbeat* restart does **not** clear them: `StartHeartbeat`,
    `RestartHeartbeat` on a DHCP-triggered VRF rebind and the HA comms restart
    all preserve `hbAuth` deliberately (#5086/#6642 — a receiver-scoped floor
    would be zeroed by every routine restart and re-admit a replayed retired
    epoch). Only a new `Manager`, i.e. restarting the daemon, resets the floor
    and admits the stranded successor on the raise-from-0 path. That is a
    heavier operation than it sounds, and it is **not** unconditionally
    preferable: a restarted floor is also a *cleared* floor, which one archived
    frame re-raises just as it re-arms a cleared latch (residual 5 below), so
    on a link an attacker is on, restarting can hand the lockout straight back.
    **When
    "Epoch session collisions" climbs alongside a peer that keeps being
    declared dead, check for a non-writable `/var` on the peer first**
    (`df`, and a test write under `/var/lib/xpf`); a clock at or before the
    Unix epoch is the second, degenerate cause. Rebinding on silence instead
    would cover every successor and is declined: waiting out the dead-peer
    interval between captures is free, so it hands the attacker back the
    unbounded churn the bound exists to stop.

    **Admission triage, measured at `20a6068b4` (#6969).** Three of the four
    findings that issue collects are LIVE, and one is not. Driving
    `heartbeatAuthState.admitAuthed` directly with a pinned `epochNowNanos`:

    | finding | state | site | measured |
    |---|---|---|---|
    | F3 third session at an unchanged epoch | **live** | `heartbeat.go:711`, `heartbeat_epoch_admit.go:263`, `:372` | sessions 1,2 admitted; 3 and 4 refused `"too many peer sessions at one boot epoch"`, `highEpochSessionCount` pinned at 2 |
    | F5 healthy peer, receiver >`bootEpochMaxSkew` slow | **FIXED by #6969** (live when measured) | `heartbeat_epoch_admit.go` | was: raise beyond the forward bound → `ok=false`. Now: an ESTABLISHED receiver admits the frame and declines the RAISE; a FRESH one still refuses. See the forward-bound section above |
    | F7 below-floor incarnation cannot progress | **live** | `heartbeat_epoch_admit.go:246` | three below-floor frames all refused, floor unchanged; `highEpoch` has one write site (`:351`, the raise path) |
    | F4 backward step persists a lower epoch | **not live as filed** | `heartbeat_epoch.go:1236` | #6711's `bootEpochPreserveMaxSkew` preserves an intact predecessor across the 2h step the issue names; only a step **beyond 30 days** still heals over one |

    F5's SCOPE is already right — the guard is `epoch > s.highEpoch && !epochWithinForwardBound(...)`,
    so equality frames are not gated. The live gap is its EFFECT: when the bound
    fires it returns false, rejecting the frame outright rather than admitting it
    *without* raising the floor. Any remedy that admits such a frame routes it
    into the same bounded per-value session budget F3 is about, so the two cannot
    be sized independently — and "raise the cap" is not available, because the
    security property is that the budget stays finite and non-refilling (a `k`
    larger than the ring restores exactly the sustained churn it closes; see
    `heartbeat.go:701-710`). F7 looks separable: it needs a re-read or re-raise
    path at `highEpoch`'s single write site rather than a change to the budget.

    **The healing side is load-bearing and hangs the suite if it is traded away.**
    Making the preserve branch unconditional — the shape "stop overwriting an
    intact higher persisted epoch" naturally takes — reds
    `TestPersistedEpochHealsOnlyWhenClockCredible_6169` and then HANGS
    `TestRefinementSamplesTheClockAfterLoadingPersistedState_6669`
    (`heartbeat_epoch_clock_sample_6669_test.go:146`), so the package run ends at
    the 600s timeout with a third of its tests never collected. #6967 records
    that the obvious fix "broke two tests and hung a third" without naming which;
    this is which.
    (`TestEqualEpochsCannotChurnTheRing_6669`,
    `TestEqualEpochSuccessorIsAdmitted_6669`,
    `TestFloorRebindsToTheRaisingIncarnation_6669`.)
    **The floor is tested BEFORE the ring is consulted and a rejected frame
    never reaches `ring.admit`.** That ordering is load-bearing: `admit`
    RECORDS a never-seen session as a side effect, so checking the epoch
    after it would let rejected replays keep evicting live watermarks and
    flush the ring — the bypass that failed review in #6370. The floor only
    rises to a value the genuine peer actually signed — but that does **not**
    bound it by the live peer's *current* epoch: if the peer has since
    regressed (residual 3, #6711), one archived frame raises the floor above
    it and locks it out, and re-raises a cleared floor after a restart just as
    it re-arms a cleared latch (residual 5).
  - **Sender** (`bootEpochSeed` published synchronously, then `refineBootEpoch`):
    `max(persisted+1, wall_clock_nanos)`,
    persisted atomically at `/var/lib/xpf/ha-boot-epoch` (the same durable
    state root as SNMPv3 `engineBoots`). The two terms cover the two
    failure modes neither survives alone — a **backward clock step** across
    a reboot is dominated by `persisted+1`, and **lost persisted state**
    (fresh image, wiped `/var/lib`, first boot) is dominated by the wall
    clock. Resolution is NANOSECONDS deliberately: a coarser seed hands two
    incarnations starting in the same interval identical values.
    **The first term is BOUNDED, and the bound is `bootEpochMaxSkew` (one
    hour).** A persisted value further ahead than that is not chained from at
    all (`epochOrderable` in `refineBootEpoch`), so a backward step LARGER
    than an hour is not carried across even with the file perfectly intact —
    see residual 3 and #6711. Read `persisted+1` as covering ordinary RTC
    skew and NTP corrections, not arbitrary clock faults.
  - **The DOWNGRADE LATCH — without it the floor closes almost nothing.**
    The floor only ever sees frames that CARRY an epoch, and an attacker's
    captures are by construction mostly from BEFORE the upgrade, so they
    carry none. A receiver that accepts epochless frames forever never
    consults the floor at all. Measured on the first cut of this change,
    with the floor latched at a live peer's epoch: **975/975 epochless
    replays still admitted.** So once the peer has been seen to emit an
    epoch, an epochless frame from it is REFUSED (`epochSeen` in
    `heartbeatAuthState`). The latch is armed by OBSERVATION, never by local
    build version — that is what keeps a rolling upgrade working.
  - **The latch is PROCESS-SCOPED, and that is the design decision that
    REPLACED durability.** It lives on `Manager.hbAuth` (#5086/#6642), so a
    heartbeat restart, a DHCP-triggered VRF rebind and an HA comms restart all
    PRESERVE it — the routine events. Only a full daemon restart clears it.

    **The cost is bounded by the peer's NEXT GENUINE FRAME — not by wall clock**,
    and that distinction is the whole of it. Measured after a receiver daemon
    restart: **1080/1080 epoch-less captures admitted** inside the window, then
    **0/120** once a genuine frame lands. What the attacker gets is one full
    ascending pass over their captures — about 60 frames across 12 retired
    incarnations — not a single frame. A replayed OLD epoch CAN set the floor low
    (the forward bound constrains only how far AHEAD an epoch may be), but it
    cannot be sustained *while the peer's own epoch is still climbing*: the
    genuine frame then dominates and re-arms the latch.

    **"The genuine frame always dominates" is FALSE as an unqualified claim, and
    this section used to make it.** It holds exactly while the sender is
    monotonic. If the peer's epoch has REGRESSED (residual 3, #6711 — a backward
    clock step larger than `bootEpochMaxSkew`), a replayed archived frame
    carrying the peer's *earlier, higher* epoch raises the floor ABOVE the live
    peer, and the live peer's genuine frames are then refused indefinitely.
    Measured: 0/5 live frames admitted after one archived frame poisoned a fresh
    floor, 0/5 after a sender restart at the same clock, and 0/5 again after a
    receiver restart followed by one re-injected archived frame
    (`TestArchivedEpochPoisonsAFreshFloor_6711`).

    With a LIVE peer that is ~100 ms and the trade is clearly good. With a
    **SILENT** peer the window stays open until the peer returns — and that is
    precisely the scenario the durable floor was justified by, so this residual
    is narrow only in the live-peer case. It is stated that way deliberately: the
    trade was taken with the silent-peer cost known, not overlooked. Measured by
    `TestReceiverRestartWindowIsOneHeartbeat_6169`.

    In exchange, rollback recovery is a PSK rotation plus `systemctl restart
    xpfd` rather than deleting a state file, there is no commit window between
    accepting a frame and durably recording it, the receive path needs no
    cross-process lock, and an in-range-but-wrong epoch cannot lock a peer out
    across reboots. The rotation is not optional garnish — a replayed archived
    epoch frame re-arms the latch against the empty post-restart state, so the
    restart alone is not reliable recovery (residual 5).

    An earlier revision persisted the FLOOR so the latch also survived a daemon
    restart. Review priced that and it was removed: a peer-floor state file
    turns a deliberate ROLLBACK into "delete the right file on the right node
    and restart" — a procedure done under pressure at 3am — opens a crash
    window between accepting a frame and committing the floor, needs
    cross-process locking on the receive path, and lets an in-range-but-wrong
    epoch lock a peer out across reboots.

    **A durable LATCH is not the same object as a durable FLOOR, and the two
    must be priced apart.** The narrowest durable latch is a PSK-scoped boolean
    — `{key fingerprint, epochSeen}` — which persists no epoch, so an in-range
    wrong floor still dies at the next restart, and which resets by
    construction on a PSK rotation. Neither floor cost above applies to it. It
    is still declined, on its own costs: the durable write has to land BEFORE
    the frame is accepted (a crash in between leaves the latch clear across the
    reboot, which is exactly the state a replay wants), so it puts storage on
    the control-channel receive path with no good failure policy — fail-open
    buys nothing over today, fail-closed lets a disk fault refuse a healthy
    peer; it needs the same cross-process lock for the same `SO_REUSEPORT`
    reason; and it makes the NO-ATTACKER rollback strictly worse, since a
    restart would no longer clear the latch and every deliberate downgrade
    would require a PSK rotation across both nodes.

    **The rotation does NOT retire captures made after it, and an earlier
    revision of this section claimed it did.** A PSK rotation retires everything
    an attacker recorded BEFORE it; a frame recorded AFTER it, under the current
    key, still verifies. **And since #6630 it retires nothing until FINALIZE**:
    while an `additional-authentication-key` window is open the retired key is
    still accepted, so the archive stays live for the whole rolling procedure.
    Retirement is step 5, not step 3. Measured: rotate K1→K2, let the peer arm the latch
    under K2, roll it back under K2 to a build that signs but emits no epoch,
    record the frames this receiver refuses, then let the peer go silent and
    restart this daemon — **5/5 of those post-rotation captures are admitted**
    against the empty state, and a durable K2-scoped latch would have refused
    them (`TestRotationDoesNotRetirePostRotationCaptures_6669`). The durable
    latch is still declined, but on its own merits:

    - **Where it matters most, its benefit and its worst cost are the same
      configuration.** A signed epoch-less frame under the current key can only
      exist if the peer held that key while running a pre-#6169 build (ALWAYS-
      EMIT means a #6169+ build always carries an epoch) — rollback, replacement
      under the same identity and key, or a partial upgrade. While the peer is
      still on that build a durable latch refuses the captures *and the live
      peer*: that is the no-attacker-rollback cost above, not a separate gain.

    A second bullet used to read **"where the live peer is healthy again, it
    shuts one door with another open beside it"** — the latch can only have
    armed under this key because an epoch-BEARING frame was accepted under it,
    so an on-link attacker holds one of those too, and against empty
    post-restart state an archived epoch-bearing frame is admitted whatever the
    latch says (residual 5). **That argument is wrong**, because the two doors
    cost the attacker different things. Measured against a restarted receiver:
    65 captured epoch-BEARING incarnations admit 325/325 on one ascending pass
    and 0/1625 across five further rounds (the floor climbs with them and the
    per-session watermark closes the rest — the set is spent), while 65
    epoch-LESS incarnations captured under the CURRENT key admit 1625/1625 and
    keep going, because nothing orders them and FIFO eviction hands back a
    never-seen session every round. That is indefinitely sustained forged
    liveness against a silent peer, and a durable PSK-scoped latch refuses all
    of it.

    So the benefit is real and is larger than "captures taken strictly inside a
    rollback": it is every epoch-less capture taken under the current key. It is
    **still declined**, on its own costs — a durable write on the accept path
    with no good failure policy, cross-process locking there, and a strictly
    heavier procedure for every no-attacker rollback — and the residual is
    **accepted**, not closed. The exposure is bounded by the rollback (no
    rollback under the current key, no epoch-less captures to replay) and is
    metered rather than silent (`Heartbeats without epoch:`). Reconsider the
    trade if a rollback under the current key ever becomes routine rather than
    an incident action.

    Rollback recovery is a rotation followed by `systemctl restart xpfd`, both
    operations operators already perform, rather than a hand-edit of state; the
    rotation carries real weight because without it the restart is defeatable by
    one replayed archived frame (residual 5).
  - **ALWAYS-EMIT, and why this mechanism costs no HA availability.** The
    epoch is published SYNCHRONOUSLY from the wall clock with **no file access
    at all**, so every frame carries one from the very first send. Persistence
    is a REFINEMENT that runs on a worker and only ever RAISES the value; its
    single job is surviving a backward clock step.

    This ordering is load-bearing, not tidiness. The latch means a peer REJECTS
    epoch-less frames from a node that has proved it emits them — so if a
    storage fault could stop this node emitting one, the latch would convert a
    disk stall into a **false peer-death**, an availability regression on an HA
    path caused by the fix itself. With emission decoupled from I/O, a hung
    disk, a blocking `flock` and a wedged `fsync` are all survivable, and the
    invariant holds:

    > a keyed heartbeat carries no epoch **iff** the peer runs a pre-#6169 build.

    The residual here is the double fault — storage that never completes AND a
    clock that stepped backwards. **That is the residual of THIS ordering
    property, not of the epoch as a whole**, and an earlier revision let it
    stand as if it were both. A single backward clock step larger than
    `bootEpochMaxSkew` regresses the epoch on its own, with storage perfectly
    healthy and the file intact — see residual 3 and #6711.
  - **The state lock fails CLOSED.** Nothing in xpf enforces a single daemon
    instance — no pidfile, and the gRPC listener sets `SO_REUSEPORT`
    (`pkg/grpcapi/server.go`), so a second `xpfd` does NOT fail on a port
    collision the way it otherwise would. `withEpochFileLock` therefore
    serializes the whole read-modify-write of the boot-epoch file across
    processes. On lock failure it SKIPS the persist rather than running the
    critical section unlocked: a lock whose failure path runs the work anyway
    is not a lock. Skipping is free precisely because emission does not depend
    on it — only backward-clock-step protection is lost.
  - **Plausibility bound — the floor is a ONE-WAY DOOR.** A latched epoch
    rejects everything below it forever, so a bogus far-future value is a
    permanent lockout. Only an epoch below **year 2200**
    (`epochPlausibleMax`) may be latched: a present-day value is ~0.25x that
    bound, `MaxUint64` is ~2.5x it (year 2554). `MaxUint64` is unreachable
    by ordinary operation but IS reachable through a corrupt or hand-edited
    persist file — and `refineBootEpoch` chaining from such a value would emit
    `MaxUint64` on one boot and then REGRESS on the next (`MaxUint64+1`
    overflows, so the wall clock wins), permanently locking this node out of
    a peer that had latched it. It therefore refuses to chain from an
    implausible previous value and rewrites the file with a sane one. The
    bound is deliberately ONE-SIDED and absolute: a low epoch is permissive
    rather than locking, so bounding below would refuse an appliance with a
    dead RTC; and an absolute bound means a receiver whose OWN clock is
    wrong does not start refusing a healthy peer. An implausible epoch still
    is refused outright rather than admitted-and-ignored: a frame the floor
    cannot ORDER would be governed by the bounded ring alone, which is the
    epoch-less bypass in miniature.
  - **Forward bound — the recoverable half.** The absolute bound alone leaves a
    single-fault path: a peer whose clock or persisted state runs far ahead, yet
    still lands before 2200, would latch a floor its own corrected incarnations
    can never climb back above. So an epoch may also be at most
    `bootEpochMaxSkew` (one HOUR, 3.6e12 ns) ahead of the RECEIVER's wall
    clock. The slack IS the worst-case lockout — a bad epoch inside the bound
    is latched, and a repaired peer sits below that floor until its own
    wall-clock seed climbs past it — so an hour is deliberate: a year of slack
    bought nothing over it (the bound only has to exceed real inter-node skew,
    milliseconds under NTP and minutes without it) and cost a year-long
    lockout. Bounding the forward side
    stops the **latch**, which is the unrecoverable half, so a peer that is
    corrected is accepted again the moment it comes back into range.
    There are exactly TWO places this forward bound is applied, and no
    persistent peer-floor store is one of them (there is no such file): the
    receiver's floor RAISE path, and `refineBootEpoch` validating the persisted
    value it would chain from — where it now also validates the successor it
    would actually publish, so a persisted value one below a bound cannot emit
    an epoch exactly on or past it.

    **Precondition on healing, stated exactly.** A persisted epoch written
    under a bad clock heals *only when this node's own clock is credible at the
    moment refinement loads the file*. Below `epochClockSaneFloor` (2020) the
    forward bound is skipped entirely — deliberately, because a dead-RTC node
    booting near 1970 cannot distinguish its own legitimate previous epoch from
    a corrupt future one. Both sit implausibly far "ahead" of a 1970 clock — a
    legitimate 2026 epoch by ~56 years, the corrupt year-2191 fixture this
    branch tests with by ~222 — and the node has no reference that separates
    them, because the forward bound that WOULD discriminate is exactly what is
    skipped. The magnitudes differ; the indistinguishability does not. Rejecting
    would
    discard exactly the value persistence exists to carry across a backward
    clock step. Only the absolute year-2200 band applies there. So on an
    appliance whose RTC is dead and whose xpfd always starts before NTP, a
    wrong-but-below-2200 value is chained from on every boot and never heals;
    refinement runs once per `Manager`, so NTP correcting the clock later does
    not re-validate it. See "Honest residuals" below.

    The forward bound gates the RAISE path only (`epoch > highEpoch`), never
    `epoch == highEpoch`. Re-testing an epoch that has ALREADY been accepted is
    a different question from vetting a new one, and conflating them was a
    defect: a backward wall-clock step beyond the skew made every subsequent
    frame from a healthy, already-latched incarnation fail the bound and be
    rejected BEFORE the monotonic `lastSeen` update, so the peer was declared
    dead in ~500ms and the cluster went dual-master. The relaxation has a
    price and it is worth naming: when the floor already sits beyond the bound,
    an equal-epoch frame from the BOUND session reaches
    `heartbeatAuthReplay.admit` and costs one ascending archive pass. That is
    the whole cost — equality cannot move the floor, so the one-way door is
    untouched, and the session binding above already refuses every other
    session at that value.

    **When the bound DOES fire on a raise, it declines the raise rather than
    rejecting the frame (#6969 F5).** The same defect the equality relaxation
    above fixed had a second half: a peer that RESTARTS while this receiver's
    clock is more than `bootEpochMaxSkew` slow presents a NEW epoch, so the
    equality exemption does not cover it, and the frame was rejected BEFORE the
    monotonic `lastSeen` update — the peer declared dead in ~500ms, dual-master,
    over a clock fault on THIS node. The bound now does what its own comment
    always said it did, gating only the irreversible operation. From an
    ESTABLISHED receiver the frame is admitted, the FLOOR IS HELD, the downgrade
    latch is NOT armed (an epoch this node cannot judge is not evidence that the
    peer signs epochs), and the session spends one slot of the same finite,
    non-refilling per-value budget an equality frame spends. From a FRESH
    receiver (`highEpoch == 0`) it is still refused outright: with no floor
    there is no established peer to strand, so refusing costs nothing and every
    fresh-state guard — refuse, never latch, leave the floor at 0 — keeps full
    strength. Recovery is automatic; once the clocks agree the next frame raises
    the floor normally, with no restart on either node.

    **What this ADMITS that was refused before**, because the change loosens a
    gate and the benefit is not the safety argument: an authenticated,
    ring-fresh, inside-the-absolute-band frame whose epoch is above the floor and
    beyond the clock's forward bound, seen by a receiver that already has a
    floor. It cannot move the floor, cannot arm the latch, and cannot churn the
    ring. Its remaining power is forged liveness from a captured frame — already
    reachable through the equality path and the post-restart archived-frame path
    (residual 5), and retired by the same PSK rotation. The one genuine widening:
    a capture from an incarnation whose epoch sits far ahead of this node's clock
    was previously unusable and is now usable for liveness and for one budget
    slot. `Epoch raises declined` in `show chassis cluster` counts both arms and
    carries the NTP guidance the rejection reason used to.

    The forward bound is applied ONLY when the receiver's own clock is itself
    credible (`epochClockSaneFloor`, year 2020). An appliance with a dead RTC
    boots near the Unix epoch and syncs NTP seconds later; during that window a
    healthy peer's epoch is ~56 years "ahead", and a naive forward bound would
    make it refuse its peer at exactly the moment cold-boot split-brain is most
    likely — the hazard `heartbeatStartupGrace` already exists for. Below that
    floor only the absolute bound applies, which is permissive, never locking.
    The trade this makes is deliberate: a backward clock step LARGER than the
    skew allowance regresses this node's epoch rather than chaining. It is NOT
    true — an earlier revision of this paragraph said it — that such a value is
    only reachable when this node's own clock was the wrong one at persist
    time, and therefore that nothing is ever locked out. An incarnation running
    at the RIGHT time persists `T` and its peer latches floor `T`; the next
    incarnation starts at `T-2h` (still credible, above year 2020), rejects the
    intact `T` for exceeding `now+1h`, publishes `T-2h`, and is refused by the
    peer. Both branches of the trade are lockouts; the choice is between one
    that is RECOVERABLE and one that never ends, because chaining from an
    out-of-range value strands this node permanently above the range its peer
    will ever accept. Recoverable does NOT mean "a restart on either node" — an
    earlier revision of this paragraph said that, and it is false; see
    "Recovery is narrower than a restart on either node" under residual 3 below
    for what actually clears it. A recoverable lockout
    beats an unrecoverable one — but the residual is real and is tracked as
    #6711, not argued away. Pinned by
    `TestRefinementValidatesThePublishedEpochNotJustThePersistedOne_6169` and
    the `value_beyond_the_forward_bound_is_not_chained_from` subtest.

    `refineBootEpoch` takes its ONE clock sample AFTER `os.ReadFile` returns,
    not before it. Sampling first let a stalled read straddle an NTP correction:
    a dead-RTC boot captured a 1970 instant, the read completed after the clock
    reached the present, and the value was then judged against the stale sample
    — so the credibility gate skipped the forward bound on a node whose clock
    was by then perfectly good, and a corrupt-but-below-2200 successor was
    published. (`TestRefinementSamplesTheClockAfterLoadingPersistedState_6669`.)
  - **Cross-process locking on the boot-epoch file** (the only epoch state file
    — there is no peer-floor file). Nothing in xpf enforces a single daemon
    instance: there is no pidfile, and the gRPC listener sets `SO_REUSEPORT`
    (`pkg/grpcapi/server.go`), so a second `xpfd` does NOT fail on a port
    collision the way it otherwise would. Two overlapping incarnations could
    therefore interleave read-modify-write, and an interleaved one can lose the
    update the other just made. An advisory `flock` on a sidecar file
    (`withEpochFileLock`) serializes the whole read-modify-write, not merely the
    write.

    **It does NOT order incarnations**, and this section used to say it did
    ("publish epochs that are not strictly ordered, which is the one property
    the whole mechanism rests on"). It serializes by lock ACQUISITION, and
    nothing ties that to daemon start or to survivorship — emission deliberately
    precedes the worker that takes the lock. Older incarnation A publishes `a`
    and is delayed; newer B publishes `b > a`, locks first, persists `b`; A locks
    second, reads `b` and raises *itself* to `b+1`. The peer then latches the
    OLDER incarnation and refuses the newer, surviving one. It cannot be closed
    with this file alone — refinement only matters when the persisted value
    exceeds our seed, and "a predecessor wrote it after a backward clock step"
    and "a concurrent newer incarnation wrote it" leave the identical file, so
    separating them needs a lifetime-held liveness lock or a writer identity in
    the file. What IS closed is the unrecoverable half: refinement is re-run on
    every later heartbeat start (`Manager.refreshBootEpoch`), so the stranded
    incarnation climbs back above the file at the next `StartHeartbeat` — a VRF
    rebind or an HA comms restart — instead of staying below the peer's floor
    for the life of the process. Between the mis-ordering and that next start
    this node is refused; there is no periodic re-check. That recovery carries
    two conditions — the raising epoch must have reached the FILE, and the
    other incarnation must be gone — spelled out under residual 7.
    (`TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669`,
    `TestBootEpochRefreshIsIdempotent_6669`,
    `TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669`.)

    **A post-rename durability failure is not a failed write.**
    `fsatomic.WriteFileDurable` reports a directory-fsync failure that happened
    AFTER the rename as a typed `*PostRenameSyncError` (#5185): the new content
    is already VISIBLE — the next read, or a restart, sees it — and only its
    durability across power loss is unknown. Refinement records its persist
    watermark from that value rather than treating the pass as a no-op.
    Treating it as a failed write left the watermark stale, so the next pass
    could not recognise its own value, chained from it, and rewrote `epoch+1`
    — ratcheting the file on EVERY pass for as long as the fsync kept failing.
    (`TestPostRenameSyncKeepsTheWatermark_6669`.)

    **It fails CLOSED — the write is SKIPPED, not run unlocked.** Proceeding
    unlocked does not trade correctness for liveness; it trades a TRANSIENT
    liveness risk for a DURABLE one. A raced read-modify-write can leave a lower
    epoch in the file, that value is read back as `prev` on the next boot, and it
    is exactly the term that matters after a backward clock step — the one case
    persistence exists for. The epoch then produced can sit below the peer's
    latched floor and be refused: the same false-peer-death, one restart later
    and durable. Declining costs only backward-clock-step protection, and only
    until the next resolve succeeds, because the wall-clock epoch is already
    published and on the wire.
  - **Layering with #4107's `peerAuthSeen` — two gates, neither redundant.**
    `peerAuthSeen` latches "the peer proved it holds the PSK" and refuses
    UNSIGNED frames; `epochSeen` latches "the peer proved it runs an
    epoch-capable build" and refuses SIGNED-BUT-EPOCH-LESS ones. A replayed
    pre-upgrade capture is genuinely signed (it came off a keyed cluster), so it
    passes the first gate and is stopped only by the second — which is precisely
    why the epoch latch was needed. An unsigned frame never reaches the epoch
    gate: `heartbeatReceiver.admitFrame` — the single implementation of the
    receive-side gate, called by `readLoop` for every datagram and by the epoch
    fixtures instead of a restated copy — reads the epoch and calls
    `admitAuthed` only when the MAC verified. The one path skipping BOTH is a
    cluster with no key configured at all, where there is no MAC to verify and
    the key-derived marker cannot exist; that is #6624's domain (an unkeyed
    chassis cluster is refused at commit), not the epoch's.

    **The wiring at both ends is bound by an end-to-end test, not by
    inspection.** `TestBootEpochTraversesTheRealSendAndReceivePath_6169` drives
    the real `heartbeatSender` through a real UDP socket into the real
    `readLoop` goroutine and asserts the receiver latched the exact epoch the
    sender published. Before it existed, passing `0` at the send site
    (`marshalHeartbeatAuthEpoch`'s last argument, which produces a byte-identical
    legacy frame) and severing the receiver's epoch read BOTH left `go test
    ./pkg/cluster` fully green — two nodes could run this code, neither latch,
    and the sustained replay stay open under passing CI.
  - **Observability — FIVE counters, and the operator action differs per
    counter.** Without them the residual is invisible: an operator who has
    upgraded both nodes has no way to tell whether the cluster is still
    accepting pre-upgrade-shaped frames, and the documentation would be the
    only defence.

    | `HeartbeatStats` field | rendered as | what a non-zero value means |
    |---|---|---|
    | `EpochlessAdmitted` | `Heartbeats without epoch:` | the exposure meter — frames admitted with no epoch at all |
    | `EpochDowngradeRejected` | `Epoch downgrades rejected:` | the latch refused a peer that had previously signed epochs |
    | `EpochSessionCollision` | `Epoch session collisions:` | too many sessions at one epoch value — usually a peer whose epoch store cannot advance |
    | `EpochOutOfBandRejected` | `Epoch out-of-band rejected:` | the PEER emitted 0 or a post-2200 epoch. A conforming build cannot; check the peer's state file or its build |
    | `EpochAheadOfClockRejected` | `Epoch ahead of our clock:` | a CLOCK fault, usually on a healthy peer — check NTP on both nodes, not for an attacker |

    The last two exist because `heartbeatAuthDecision` cannot tell those arms
    apart: it sees only `nonceFresh == false` and reports every epoch refusal as
    `stale nonce (replay)`. Both arms used to be silent as well as mislabelled,
    so a clock-skew lockout and a corrupt-epoch peer both read as an on-link
    replay attack. `admitAuthed` now returns a reason for each and the receive
    path prefers it over the generic wording. The third silent arm — an epoch
    BELOW the floor — keeps the generic wording deliberately: that one really is
    a replay of a retired incarnation.

    **The `heartbeatAuthDecision` arms carry reasons too, and they are bound
    (#6968).** The epoch override above only helps when `admitAuthed` ran, and
    it does not run on a bad MAC (`if macOK { nonceFresh, epochReason = ... }`).
    So a forged or tampered frame's reason comes from `heartbeatAuthDecision`'s
    OWN `!macOK` arm — and that arm's correctness rests entirely on ARM ORDER:
    a failed MAC leaves `nonceFresh` at the zero value `false`, so if the
    `!macOK` arm is removed the frame falls through to `!nonceFresh` and an
    attacker with the wrong PSK is reported as `stale nonce (replay)`. The
    frame is refused either way — this is a MISATTRIBUTION, never a fail-open —
    which is exactly why no admission test could see it. Measured on
    `63ef1fad6`: `if !macOK` -> `if false` left `go vet` at rc=0 and the whole
    package GREEN. `TestHeartbeatAuthDecisionReasonNamesTheArm_6968` now
    asserts the exact reason per arm (and that the arms' strings are pairwise
    DISTINCT, or the assertions would be vacuous), and
    `TestForgedHeartbeatIsNotReportedAsReplay_6968` binds the same property
    through a genuinely forged frame so `macOK` is derived rather than
    hand-set. **Adding an arm here means adding its reason to that table.**

    All five are rendered on all three surfaces
    (`FormatInformation`, `FormatStatistics`, `FormatControlPlaneStatistics`)
    and bound there by `TestEveryEpochCounterIsRendered_6669`, which drives each
    counter to a DISTINCT value so a transposed pair of render lines fails
    rather than passing on a label match.

    Every one is RENDERED in the `Control link statistics:` block on all three
    surfaces that print it — `FormatInformation`, `FormatStatistics` and
    `FormatControlPlaneStatistics` — under the labels in the table above. While the peer is not yet signing epochs the
    count carries an inline note naming the action that closes it (rotate the
    control-link PSK); once the latch has armed the note switches to marking the
    count historical, since it is then a record of the migration rather than
    live exposure. A counter populated on an internal struct but rendered
    nowhere would be documentation, not observability, so the guard asserts the
    RENDERED string on each surface rather than the struct field.

    **Not yet a Prometheus series.** The collector (`pkg/api`, `xpfCollector`)
    is dataplane-scoped and has no cluster/heartbeat surface at all, so this
    would mean plumbing the cluster `Manager` into it — a new dependency edge,
    not a one-line addition. Worth doing as its own change; the CLI block is
    what an upgrading operator reads today.
  - **Sender nonce is INCARNATION-scoped** (`Manager.heartbeatNonce`). It
    used to be per-`heartbeatSender`, so every `StartHeartbeat` minted a
    fresh session — and routine events mint them (VRF rebind, comms
    restart). One long-lived daemon could therefore emit more than a ringful
    of sessions under ONE epoch, which the floor cannot separate, leaving
    the ring churnable within an incarnation. One incarnation now emits one
    session with a counter monotonic across heartbeat restarts, so the floor
    leaves an attacker at most one session and the ring rejects it on the
    watermark. Nothing regresses on the receiver: a heartbeat restart keeps
    the session and advances the counter (admitted); a daemon restart builds
    a new `Manager` and draws a fresh session (admitted as never-seen).
  - **What happens on a ROLLBACK — the one legitimate latch trigger.**
    Because a storage fault no longer stops a node emitting an epoch, the
    only way a healthy peer goes epochless after having emitted one is a
    deliberate rollback to a pre-#6169 build (A/B image rollback, #1930).
    That peer IS refused: this node declares it dead and takes over, and the
    rolled-back node cannot see that it is being refused. This is a real,
    deliberate trade — the same one #4107's sticky `peerAuthSeen` already
    makes for the auth trailer. It is bounded and
    operator-visible:
      - a cluster that has never run an epoch-capable build is never latched,
        so a plain rolling upgrade in either direction is unaffected;
      - the rejection logs a rate-limited, actionable warning naming the
        recovery below (`Manager.NoteEpochDowngradeHeartbeat`, once per 30s) —
        there is no state file, so nothing to clear by hand. The generic
        per-frame `heartbeat auth rejected` line is rate-limited on the same
        30s interval (`heartbeatRejectWarnLimiter`) and reports
        `suppressed_since_last`, so the bound does not hide the rate. Before
        #6669 r18 only the actionable line was bounded and the generic one
        fired per frame, so a 10/s epochless stream produced ~10 warnings a
        second — the sentence promised a rate limit the noisy line did not
        have;
      - the archived-frame replay that re-arms the latch is ALSO admitted, so
        it refreshes `lastSeen` and feeds `handlePeerHeartbeat`: a peer that is
        DEAD looks alive for as long as the replay continues, and that liveness
        feeds election. One frame per dead-peer interval sustains it. This is
        NOT introduced by #6169 — master has no epoch gate at all, so the bare
        replay ring admits the same frame after the same receiver restart, and
        `TestHeartbeatRestartStillAcceptsGenuinePeer_5086` REQUIRES that (a
        genuine peer reboot must be accepted). The epoch floor strictly
        improves on master once armed and does not close the post-restart
        window. The recovery below retires it by the same mechanism as the
        latch half, because it is the same replay;
      - **recovery, in this order:** rotate the control-link PSK on BOTH nodes,
        *then* `systemctl restart xpfd` on the node that is refusing. The latch
        is process-scoped, so the restart brings it back unlatched and it
        accepts the rolled-back peer again. There is no state file to hand-edit
        and no new CLI surface to learn. Rolling BOTH nodes back needs no
        action beyond that on whichever node had latched.

        **If you already did it in the wrong order, you are not stuck — restart
        once more.** Restarting *before* rotating leaves the latch armed
        THROUGH the rotation: the replay re-arms it after the restart, and the
        subsequent key change cannot un-arm what is already set. Measured, one
        rotate→restart pass recovers; restart→rotate needs a **second** restart
        after the rotation. Nothing else is required, and no state is lost
        either way.

        **The restart alone is not reliable, and the order is the reason.**
        A restart clears the floor, the latch and the ring together, and
        arming the latch needs only an authenticated, orderable, ring-fresh
        epoch frame — so ONE frame an attacker captured while the peer still
        ran an epoch-capable build re-arms it against that empty state
        (`highEpoch` is 0, so nothing is below the floor; an empty ring calls
        its session never-seen). The rolled-back peer is refused again, and one
        replay per restart sustains that indefinitely. Rotating the PSK first
        makes every archived frame fail MAC verification, so it never reaches
        the latch; the key is re-read per frame on both the send and receive
        paths, so rotation itself needs no restart.

        **Since #6630, "rotated" means rotated THROUGH FINALIZE.** While an
        `additional-authentication-key` window is open the retired key is still
        ACCEPTED, so an archived frame signed under it still verifies and still
        reaches the latch. Run the rolling procedure to step 5 (`delete chassis
        cluster additional-authentication-key` on both nodes) before treating
        the archive as retired — or, for this recovery specifically, rotate
        without opening a window at all and take the ~1 s liveness gap
        knowingly, since the cluster is already in a refusing state.

        This is pinned by
        `TestArchivedEpochReplayReArmsLatchAfterRestart_6169` and stated at the
        arming site in `admitAuthed`, which also records why a durable
        latch and a freshness test were both rejected.
  - **Honest residuals**, each measured rather than asserted.
    1. **Receiver restart window — bounded by the peer's next genuine frame, not
       by time.** ~100 ms with a LIVE peer; **open until the peer returns if it is
       SILENT**, which is the case durability existed for. Measured: 1080/1080
       epoch-less captures admitted inside the window, 0/120 after a genuine
       frame lands; the attacker gets one full ascending pass (~60 frames across
       12 retired incarnations). A replayed old epoch can set the floor low but
       cannot sustain it **while the peer's own epoch is still climbing** — the
       genuine frame then dominates. It does NOT dominate if the peer's epoch has
       regressed (residual 3): there a replayed archived frame raises the floor
       above the live peer and holds it out, across receiver restarts, at one
       re-injection each.
       (`TestReceiverRestartWindowIsOneHeartbeat_6169`,
       `TestArchivedEpochPoisonsAFreshFloor_6711`.)
    2. **In-bound clock skew latches a bounded lockout.** A peer epoch ahead of
       us but INSIDE the skew allowance is latched, so a peer later repaired to
       real time sits below that floor. Bounded twice: the slack IS the lockout
       (one hour), which bounds how far a NEW incarnation of the peer has to
       climb — **not** a window the RUNNING sender waits out. An earlier
       revision of this list said the peer's seed "climbs past it unattended";
       that was false. The rejected sender resolved its epoch once at boot and
       caches it for the life of the process (`bootEpochOnce`), so waiting
       changes nothing it emits: recovery is a **sender restart** on the peer,
       or a receiver restart, never elapsed time alone
       (`TestRunningSenderDoesNotRecoverByWaiting_6669`). The floor is in
       memory, so `systemctl restart xpfd` on the refusing node clears it
       immediately — subject to residual 5, since a replayed
       archived frame can re-raise a cleared floor just as it can re-arm a
       cleared latch. With a durable floor this needed deleting a state file,
       which is what made it a MAJOR.
       (`TestInBoundFarFutureEpochLockoutIsBounded_6169`.)
    3. **Sender epoch regression — and it is NOT only a double fault.** Losing
       the persisted epoch AND stepping the clock back below the last emitted
       value in the same reboot regresses the sender's epoch and the peer
       refuses it, with the same restart recovery as a rollback. This
       paragraph used to end "both terms of the seed must fail together", and
       that margin does not hold: a SINGLE backward step larger than
       `bootEpochMaxSkew` (one hour) does it on its own with the persisted file
       perfectly intact, because `refineBootEpoch` declines to chain from a
       value more than an hour ahead of `now`. The peer had latched the earlier,
       correct epoch, so it refuses the restarted node; a later NTP correction
       does NOT repair it, since the epoch is published once per incarnation and
       the file is NOT overwritten (#6711: `bootEpochPreserveMaxSkew` preserves
       a persisted value that could be an intact predecessor), so correcting the
       clock and restarting chains from it and clears the floor at once. Before
       that fix the file held the lower value and recovery had to wait for wall
       time to climb back past the old floor.

       **Recovery is narrower than "a restart on either node".** Restarting the
       SENDER does not help *while its published reading is still below the
       floor* — the file now holds the *lower* value, so the next incarnation
       re-publishes from the same bad clock (measured: still below the floor).
       The operative condition is the reading, not the clock: a clock that stays
       two hours slow still reads past the floor two real hours later, and a
       restart then publishes a value STRICTLY ABOVE it, which the peer admits
       on the RAISE path and which rebinds the floor to that incarnation.
       The raise path is the one to rely on, and not because equality is shut:
       a frame landing exactly ON the floor is admitted while one of the
       value's `heartbeatEpochSessionsPerEpoch` slots is free, so that door is
       real but finite and does not refill. The raise is the wider of the two
       (a nanosecond past the floor, rather than landing on one exact value)
       and cannot be exhausted
       (`TestPoisonedFloorStillRecoversByRaise_6669`). Restarting the RECEIVER does
       clear the floor, but an attacker holding one archived frame from the
       pre-regression incarnation re-raises it immediately, at one re-injection
       per restart — the same shape as residual 5, and it means the floor can be
       poisoned by a capture rather than only by the sender's own regression.
       Reliable recovery is fixing the clock (then restarting the sender), or a
       PSK rotation before the receiver restart. Tracked as **#6711** — a
       behavioural fix there touches persistence semantics and is deliberately
       out of scope here. (`TestArchivedEpochPoisonsAFreshFloor_6711`.)
    4. **PSK rotation** changes the key-derived marker; the in-memory floor and
       latch are unaffected and stay valid, since a floor is a per-peer counter
       rather than key material.
    5. **A restart does not recover from a rollback while an archived epoch
       frame is being replayed.** Restarting clears the floor, the latch and the
       ring together, and arming needs only an authenticated, orderable,
       ring-fresh epoch frame — so ONE frame captured while the peer still ran
       an epoch-capable build re-arms the latch against that empty state and the
       rolled-back peer is refused again, indefinitely, at one replay per
       restart. The same shape re-raises the floor in residual 2. Recovery is
       PSK rotation on both nodes FIRST, then the restart, which is what the
       rejection warning now says. Scope: a peer that has NEVER emitted an epoch
       cannot be falsely armed this way — there is nothing to capture — so this
       bites on rollback, replacement under the same identity and key, or a
       partial upgrade. Not closed in code: a durable FLOOR re-creates the
       peer-floor file this design deliberately removed; a durable PSK-scoped
       LATCH avoids that but pays a durable write on the accept path, a
       cross-process lock there, and a heavier no-attacker rollback. It is
       **not** declined as redundant: a rotation retires captures taken *before*
       it and nothing else, and a durable latch refuses the epoch-less captures
       taken under the CURRENT key — the ones that sustain forged liveness
       indefinitely (1625/1625 admitted after a restart, against 0/1625 for a
       spent epoch-bearing set). The pricing is above; and
       a freshness test needs a challenge-response or timestamp the wire format
       does not carry (a legitimately long-lived peer's epoch is arbitrarily
       old, so no recency test separates it from an archived one).
       (`TestArchivedEpochReplayReArmsLatchAfterRestart_6169`,
       `TestRollbackRecoveryOrderingIsRotateThenRestart_6169`.)
    6. **A bad persisted epoch heals only if the local clock is credible when
       refinement loads it.** Below `epochClockSaneFloor` the forward bound is
       skipped, so a wrong-but-below-2200 persisted value is chained from rather
       than ignored. On an appliance with a dead RTC whose `xpfd` starts before
       time sync, the FIRST pass of every boot is made against an uncredible
       clock, and a correctly clocked peer then refuses this node's epoch on its
       raise path — asymmetric visibility, not mutual isolation. Refinement is
       re-run at each later heartbeat start (`Manager.refreshBootEpoch`), which
       RE-VALIDATES the file but does **not** heal it — an earlier revision of
       this paragraph said it did, and that was wrong. Refinement persists the
       published epoch, which only ever rises, so once the first pass has chained
       from the corrupt value every later pass writes the same raised value back.
       Nothing lowers the file, and lowering is what healing would mean. On the
       dead-RTC box this residual describes, a restart does not clear it either:
       the first pass of every boot chains again and the value ratchets. No
       complete close exists:
       under a dead RTC a legitimate previous epoch and a corrupt future one are
       indistinguishable (nothing on the node is a trustworthy time reference),
       and healing after the fact would mean LOWERING a published epoch
       mid-incarnation, the one direction the design refuses. A PARTIAL
       narrowing does exist and was declined rather than missed — lowering the
       arbitrary year-2200 horizon would reject a year-2191 value while still
       carrying present-day ones — because the horizon is a hard cliff, not
       spare room: a value at or past it is rejected outright on EVERY frame, so
       lowering it makes a forward clock fault that much more likely to produce
       mutual refusal. That trades a fault whose worst case is asymmetric
       visibility for one whose worst case is dual-master. Reasoned at
       `epochWithinForwardBound`. Operational close: a working RTC, or ordering
       `xpfd` after time synchronization.
       (`TestPersistedEpochHealsOnlyWhenClockCredible_6169`.)
       Refinement's clock sample is taken AFTER the state read returns, so a
       stalled read straddling an NTP correction cannot judge the file against a
       clock that no longer exists
       (`TestRefinementSamplesTheClockAfterLoadingPersistedState_6669`).
    7. **The state lock orders lock acquisition, not incarnations.** Two
       overlapping `xpfd` instances (no pidfile, `SO_REUSEPORT`) can publish in
       one order and reach `withEpochFileLock` in the other: the OLDER one locks
       second, reads the newer one's persisted value, and raises *itself* above
       it. The peer then latches the older incarnation and refuses the newer,
       surviving one. It cannot be closed with this file alone — a predecessor's
       value after a backward clock step and a concurrent newer incarnation's
       value leave the identical file — so a complete fix needs a lifetime-held
       liveness lock, a writer identity in the file, or single-instance
       enforcement for `xpfd`. What IS closed is the unrecoverable half:
       refinement re-runs on every later heartbeat start
       (`Manager.refreshBootEpoch`), so the stranded incarnation climbs back
       above the file at the next `StartHeartbeat` instead of staying below the
       floor for the life of the process. Until that start it is refused, and
       there is no periodic re-check. Tracked as **#6724**.
       (`TestConcurrentIncarnationsAreOrderedByLockAcquisition_6669`,
       `TestBootEpochRefreshIsIdempotent_6669`.)

       **That recovery carries two conditions**, and they do NOT need the same
       missing state — an earlier revision of this paragraph said both were the
       same state as the mis-ordering itself. It re-reads the FILE, so it
       recovers only what the file expresses. First, **the floor-raising epoch
       must have reached the file**: refinement publishes a raise before
       persisting it (deliberately — a node that has read a predecessor's higher
       value must still order itself above it even when it cannot write), so the
       other incarnation can EMIT `b+1` while the file still reads `b`. This
       node then has no signal at all — it wrote `b`, the file says `b` — and
       every restart returns at the idempotence shortcut, leaving it below the
       peer's floor for its whole process lifetime. Second, **the other
       incarnation must be gone**: while both run, each pass raises above the
       other and rewrites the file, so they leapfrog indefinitely, alternately
       stranding each other while the file ratchets.
       (`TestRefineRecoveryNeedsTheRaisingEpochInTheFile_6669`.)

       Only the SECOND needs a writer identity in the file or a lifetime-held
       liveness lock, which is where the leapfrog lives. The first needs nothing
       but a **retry trigger**: on a retry A's published value is already `b+1`,
       so `next := prev+1` does not exceed it, nothing ratchets, and the
       `WriteFileDurable` is simply re-attempted — once `b+1` lands, B's next
       refresh reads it and raises to `b+2`. What is missing is only something
       to schedule that retry, which is the "no periodic re-check" half of
       **#6724** and a materially smaller change than a writer identity.

       A refine requested while one is in flight used to be DROPPED, which lost
       exactly this recovery request — the in-flight worker's locked read can
       already be complete, so an update landing behind it is invisible to that
       pass. It is now COALESCED into one follow-up pass, which bounds the extra
       work at one outstanding request rather than an unbounded backlog of
       fsync-ing workers. (`TestOverlappingRefineRequestIsCoalesced_6669`,
       `TestCoalescingDoesNotRatchetOnAHealthyNode_6669`.)

       **The in-flight flag and the pending bit are ONE WORD**
       (`Manager.bootEpochRefine`, claimed and released by CAS on the pair) and
       that is a correctness requirement rather than packing. As two separate
       atomics they could be observed torn: a requester that read "a worker is
       in flight", lost the race while that worker ran all the way out, and only
       then stored the pending bit published it against a worker that no longer
       existed, and nothing in production observes a stranded bit — the operator
       would have seen only a node still below its peer's floor, recovering at
       some later heartbeat start that nothing bounds. On one word the publish is
       conditional on the observation still holding, so a requester whose CAS
       fails takes the idle slot and runs the pass itself. The window was a few
       instructions wide and unreachable by hammering (3000 rounds x 4 concurrent
       `refreshBootEpoch`), so it is driven through two seams.
       (`TestLateRefineRequestIsReclaimed_6669` for a request landing before the
       release, `TestLateRefineRequestCannotBeStranded_6669` for one landing
       after.)

       **`Manager.Stop` joins the worker, with a bound.** The worker may park
       indefinitely in a flock or an fsync, so it outliving `Stop` needs no race
       — one sequential shutdown over a wedged store reaches it — and it would
       then still be storing to `m.bootEpoch` and writing the state file on a
       torn-down manager. `Stop` refuses new workers and waits
       `bootEpochStopJoinBudget` (2 s) for the one already running; the wait is
       bounded because the shutdown path has just sent VRRP priority-0 and must
       not block on a dead disk. A timeout is logged, and leaves behind atomic
       stores and **up to two** `fsatomic` writes: the wedged pass itself, plus
       one coalesced follow-up if a request set the pending bit while it was
       stuck, which the worker serves once it unblocks.

       **The join spawns nothing, and takes no lock.** Writing it as
       `go func() { wg.Wait(); close(done) }()` selected against a timer returns
       only the CALLER — nothing cancels a `WaitGroup.Wait` — so each timed-out
       join left one goroutine parked for as long as the store stayed wedged.
       That is easy to wave through for a single terminal `Stop` and wrong
       across repeated calls, and there are several (`Stop` is public; the tests
       join on every epoch case). The worker publishes its own exit handle
       (`Manager.bootEpochWorker`, an `atomic.Pointer`), so a join is a select
       on a channel somebody else closes and a timeout costs nothing.
       (`TestTimedOutJoinLeavesNoWaiterBehind_6669`.)

       The handle is PUBLISHED under `bootEpochRefineMu`, which is what keeps
       `Stop`'s refuse-then-join ordering airtight, but it is LOADED and CLEARED
       without it — and that is a correctness requirement, not tidiness.
       `bootEpochRefineMu` is held across `claimBootEpochRefine`, hence across
       its `epochRefineAfterLostClaim` seam, where a requester can park
       indefinitely; the join and the worker's own exit are precisely the two
       operations that must make progress regardless. Guarding the handle with
       that mutex deadlocked all three against each other, and a bounded join
       that can block forever is not a bounded join.
       (`TestJoinDoesNotBlockBehindAParkedRequester_6669`.)

       It can also still hold a lock a caller waits on, which an earlier
       revision of this section denied: `withEpochFileLock` holds the state
       file's advisory lock across the whole read-modify-write, so another
       INCARNATION's refine blocks behind a wedged worker until it unwedges.
       Nothing in *this* process does — the refine slot is a CAS word, not a
       lock.

       **The timeout path deliberately does not release that flock.** The
       descriptor is a local on the wedged worker's stack, and dropping the lock
       while that worker is still mid-write would let another incarnation
       interleave with a write in progress — trading a delay for the torn update
       the lock exists to prevent. It does not need releasing: an flock dies
       with the open file description, so the kernel drops it when the process
       exits, SIGKILL included. Under the documented restart recovery (systemd
       `Type=simple`, `TimeoutStopSec=20`) the old unit is reaped before the new
       one starts, so a **restart never contends for this lock**. What can
       contend is two concurrently running incarnations — the SO_REUSEPORT
       overlap this lock was written for — and there the blocked party is the
       other incarnation's refine worker, whose failure is already survivable:
       it declines the persist and keeps the wall-clock epoch already on the
       wire.

  - **`Stop` is not idempotent by construction, only by call topology.** It has
    no `sync.Once` and no early return; a repeat call re-executes the body and
    survives only because it captures `hbSender`/`hbReceiver` under `mu` and
    nils them there, while `Monitor.Stop` is independently idempotent through
    the same idiom. Both `heartbeatSender.stop` and `heartbeatReceiver.stop`
    open with a bare `close(stopCh)`, so a second call without that capture
    panics. The manager is built once per process and stopped once, so the
    repeat is unreachable today — but by topology, not by design, which is why
    `TestSecondStopIsANoOp_6669` asserts it.

       **Three rules for tests in this area**, each of which was a real
       cross-test failure before it was a rule:

       1. `bootEpochReady` **is not a drain.** The worker closes it from inside
          its loop and then still calls `releaseBootEpochRefine`, which reads a
          package-var seam, and may run further coalesced passes. Use
          `awaitFirstRefine`, which waits for the channel AND drains.
       2. **Unpark every seam on the failure path**, from a `t.Cleanup` rather
          than the end of the body. `t.Fatalf` runs `runtime.Goexit` and skips
          the rest of the body, so an assertion that fires while a requester is
          parked inside `claimBootEpochRefine` leaves that goroutine holding
          `bootEpochRefineMu` for the life of the process — and every later test
          that starts or stops a worker then blocks on it, turning one
          assertion into a package-wide `panic: test timed out` naming an
          unrelated test.
       3. **Join a requester goroutine; do not poll the word for it.**
          `waitBootEpochIdle` reads `bootEpochRefine`, and that word reads 0 in
          the window after a worker releases the slot and before an unparked
          requester re-claims it, so a test can return while the requester is
          still inside `startBootEpochRefine` reading `bootEpochPath`.
          `keyedEpochManager`'s cleanup join is no backstop: it joins a
          REGISTERED worker, and a requester that has not claimed yet is not
          one.
  - **No clone/bake requirement** (unlike the SNMPv3 engine-id, `pkg/snmp`).
    Epochs are compared per-PEER, never between the two nodes, so two chassis
    cloned from one image may hold identical persisted boot epochs harmlessly;
    and a baked-in value can only ever raise a node's starting epoch, which the
    never-regress rule already permits.
- **The tracker's LIFETIME is the process, not the heartbeat (#5086).**
  The watermarks and the sticky `peerAuthSeen` flag live in
  `Manager.hbAuth` (`heartbeatAuthState`); a `heartbeatReceiver` holds a
  POINTER to it. This is load-bearing, not a refactor. Every
  `StartHeartbeat` builds a brand-new receiver, and it runs on far more
  than a daemon boot — `RestartHeartbeat` on a DHCP-triggered VRF rebind
  (`daemon_apply_dataplane.go`) and the HA comms (re)start
  (`daemon_ha_sync.go`), both routine. While the tracker was a receiver
  field, each of those DISCARDED every retired-session watermark, so the
  #5477 protection lasted only as long as one UDP socket: after a restart
  an attacker replaying captured frames from a retired session hit an
  EMPTY tracker, every frame looked never-seen, and the whole captured run
  was re-admitted — refreshing peer liveness and applying stale
  role/priority for its full length. Measured on the pre-fix code: a
  10-frame capture from each of two sessions yields 20 admitted frames
  (~4 s of forged liveness at the 200 ms interval, i.e. 4× the ~1 s
  peer-dead window) per heartbeat restart, and a fresh 20 on every
  subsequent restart. A peer that looks alive while dead is the failure
  that matters here: the survivor never takes over. Anchoring the state to
  the `Manager` costs nothing on the failover path (the same integer scan,
  now under a mutex taken ~5×/s) and does not change the memory bound —
  one fixed ring per `Manager` (64 × 16 B = 1 KiB) plus a mutex and an
  atomic, allocated once, never growing with restart count, uptime, or the
  number of peer sessions observed. It also fixes the mirror-image
  hole in `Manager.HeartbeatPeerAuthSeen`, which read the flag off
  `m.hbReceiver`: `StopHeartbeat` nils that field, so every restart
  silently DISARMED the gRPC fabric listener's downgrade-guard for the
  restart window (a VRF-rebind restart retries the bind for up to ~5 s)
  and an unsigned fabric RPC was accepted from a peer already known to
  hold the key. It now reads the process-lifetime state.
  **Narrowed, not closed, by #6169:** the session ring, the boot-epoch floor
  and the downgrade latch are all process state, so a full daemon restart
  starts with all three empty. What #6169 changes is how fast that repairs:
  the peer's next epoch-bearing frame re-establishes the floor above every
  captured older epoch and re-arms the latch, so the exposure is bounded by
  the peer speaking rather than by the ring alone. With a SILENT peer the
  window stays open until it returns — see the boot-epoch residuals above.
- **Dual-accept (rolling upgrade), `heartbeatAuthDecision`.** Mirrors
  the #4126 VRRP-checksum dual-accept migration:
  - No local key → accept everything (this node cannot verify; may be
    the not-yet-keyed side of an upgrade). No regression.
  - Local key + auth trailer → enforce: reject a bad HMAC or a replayed
    nonce.
  - Local key + no trailer + peer has NOT yet authenticated → accept
    (the peer has not started signing; key not yet synced).
  - Local key + no trailer + peer HAS authenticated (sticky
    `peerAuthSeen`, set only by a verified frame) → reject: a downgrade
    to cleartext once both nodes are keyed is an attack.

  Enforcement therefore engages only once BOTH nodes carry the key and
  are observed signing — a mixed-version / mid-key-rollout cluster never
  splits.
- **Operator surface (#4484 L-9).** `FormatControlPlaneStatistics`
  (`show chassis cluster control-plane-statistics`) renders an
  `Authentication:` line derived from `controlLinkAuthStatus()`, so an
  operator can tell whether the control link's HMAC auth is actually
  **engaged** (`engaged (peer authenticated; unauthenticated frames
  rejected)` — both nodes keyed and signing) or running in
  **dual-accept** grace (`dual-accept (no control-link key configured)`
  or `dual-accept (key configured; peer not yet authenticated)`). It is
  computed from the SAME two facts the auth gates use —
  `ControlLinkAuthKey` presence + `HeartbeatPeerAuthSeen` — so the line
  tracks the real enforcement decision, and it inspects only `len(key)`
  so the secret is never rendered. Before this line, a control link
  silently degraded to dual-accept (e.g. a peer that stopped signing)
  was invisible.
- **Secret hygiene.** The key is `config.Secret`, redacted on every
  JSON/YAML/`String()` path and masked as `##SECRET-DATA##` in raw-AST
  renders (`authentication-key` is already in `ast_redact.go`'s secret
  set). It is stored as raw bytes on the `Manager`, never logged; the
  auth-reject log line carries only a reason string and the peer node id.

**Scope.** PR-A authenticates the heartbeat/election channel. PR-B (this
work) extends the SAME PSK to the **fabric gRPC listener**
(`pkg/grpcapi/fabric_auth.go`): the `Manager.ControlLinkAuthKey()`
accessor exposes the raw key to `pkg/grpcapi`, which HMAC-authenticates
every peer-proxied RPC with a time-windowed bearer token on top of the
#4122 allowlist (see `docs/architecture.md` "Cluster fabric gRPC
listener" and the F1 half of #4107). The fabric path reuses this
package's dual-accept posture (`fabricAuthDecision` mirrors
`heartbeatAuthDecision`).

The fabric downgrade-guard arms off the heartbeat, not just the fabric
channel. This package exposes `Manager.HeartbeatPeerAuthSeen()` — true
once the receiver accepts a valid authed heartbeat from the peer (the
sticky `peerAuthSeen` in `Manager.hbAuth`, an `atomic.Bool` because it is
read cross-goroutine; it hangs off the Manager rather than the receiver so
a heartbeat restart cannot disarm the guard — #5086). The gRPC interceptor rejects a tokenless fabric
call when EITHER a prior valid fabric token OR the heartbeat has armed
enforcement. Rationale: nothing periodically dials the fabric listener,
so arming only off an on-demand fabric RPC would leave a window after
EVERY restart of a keyed node — until the next cross-node command — where
any on-segment host could drive tokenless `ClearSessions` / cross-node
failover. Heartbeats flow every ~200ms, so arming off them closes that
window to one interval. Dual-accept is preserved: a not-yet-keyed peer
signs neither channel, so neither source arms during a rolling upgrade.
Two residuals are accepted, not bugs: (1) the ~1-window token replay
horizon (removed only by mTLS with per-node certs, deferred with #4047);
(2) a wall-clock skew > the ±1-window tolerance (~60–90s) fails cross-node
fabric RPCs `Unauthenticated` until corrected — a > 30s inter-node skew is
an operational NTP fault (NTP is already a cluster prerequisite for
heartbeat clock-sync and session-timestamp rebasing).

**Session-sync stream auth (F23, done — `sync_auth.go`).** The
**session-sync stream** frames (`sync.go` / `sync_conn.go` /
`sync_protocol.go`) are now authenticated with the SAME control-link PSK.
The heartbeat's trailing-HMAC does NOT work here: the stream is
length-framed, so a legacy reader would mis-frame an appended HMAC as the
next header. F23 instead uses an auth **capability handshake at connection
setup** that negotiates — BEFORE any session frame flows — whether the
connection is authenticated, then seals every subsequent frame.

- **Handshake (`performSyncHandshake`).** Only a node that holds the PSK
  runs it. Since #7163 it is **Noise_NNpsk0**: the dialer writes msg1 in a
  `syncMsgAuthHello` (type 27) frame and the accepter answers with msg2 in a
  `syncMsgAuthProof` (type 28) frame. The frame TYPES are unchanged; their
  payloads are not, and neither is the turn order — under Noise the accepter is
  the RESPONDER and speaks only after reading msg1, where the old handshake had
  both symmetric peers writing a HELLO concurrently. See "Session-sync
  authentication is Noise_NNpsk0 (#7163, closing #5078)" above for what each
  binding comes from, and for why this is a flag day rather than an additive
  change. The nonce exchange, `syncAuthProof`, `syncCheckPeerNonce` and
  `syncDeriveFrameKey` are DELETED, not left unreferenced: every one of them
  existed to approximate a property the pattern now supplies by construction,
  and an unused HMAC-over-a-nonce helper is what the next author reaches for.
- **Per-frame seal (`authConn.sealFrame` / `verifyFrame`).** On an
  AUTHENTICATED connection every frame gets an 8-byte per-connection
  monotonic sequence + a 32-byte HMAC keyed by a per-connection, **per
  direction** key — since #7163 the two keys `Split()` returns, where the
  pre-#7163 derivation handed both directions the same bytes. The frame FORMAT
  is deliberately unchanged: the defect being closed is the KEY, not the seal,
  and replacing both in one flag day would put two independent wire changes in
  one change. The receiver rejects a bad
  HMAC (forgery/tamper) or a non-increasing sequence (replay/regression) and
  drops the connection. `writeFull` is the single chokepoint that seals (all
  writers hold `s.writeMu`, so sequence order equals wire order);
  `receiveLoop` is the single reader that strips + verifies the trailer.
  Chose a signed per-frame trailer over a bare sequence because a sequence
  without a MAC is forgeable (an on-path attacker just uses seq+1); the MAC
  cost is negligible at realistic session-sync rates.
- **Dual-accept, UNKEYED SIDE ONLY (as of #5078).** A node with no key never
  handshakes and is byte-for-byte a legacy peer, so an unkeyed node still
  accepts anything. A KEYED node does **not** dual-accept: it rejects a
  legacy/unkeyed peer (no HELLO, or `keyed=0`) outright, with no
  first-contact grace and no migration window — see "Session-sync
  fail-closed authentication (#5078)" above, which supersedes the
  paragraph this bullet used to contain. The `pendingFrame` mechanism that
  carried a legacy peer's first frame out of the handshake is **deleted**,
  not merely bypassed: with no accepting arm left it was unreachable, and
  it executed that frame BEFORE the connection was admitted. Enforcement
  still engages only once BOTH nodes are keyed and signing — and, for an
  ALREADY-ESTABLISHED connection, only after it is re-established, because
  the handshake result is fixed at connect and committing a key does not
  restart cluster comms (#6628, pinned by
  `TestAuthKeyChangeDoesNotRestartClusterComms_5078`; see "Operating the
  control-link PSK" below).
- **No sync-side downgrade-guard (removed in #5078).** There used to be one
  here: once the peer had authenticated on the sync channel (sticky
  `syncAuthedEver`) or the heartbeat channel, a later UNAUTHENTICATED
  connection was rejected. A guard of that shape only matters where an
  unkeyed peer would otherwise be ADMITTED, and on a keyed node none ever
  is, so it became unreachable — `syncPeerAuthSeen` ended with zero callers
  and `syncAuthedEver` write-only — and was deleted along with the
  `HeartbeatPeerAuthSeen()` requirement on `SyncAuthProvider`. The **#4107
  heartbeat downgrade-guard is separate state** (`heartbeatAuthDecision`
  over `heartbeatAuthState.peerAuthenticated`) and is unchanged, as is the
  #4357 fabric guard that arms off it via `Manager.HeartbeatPeerAuthSeen`
  — that method is still exported and still consumed, just no longer by
  this interface.
- **Wiring.** `SessionSync.SetAuthProvider(*Manager)` (`daemon_ha_sync.go`)
  supplies `ControlLinkAuthKey()`. No new
  config leaf — the same `set chassis cluster authentication-key` secret
  authenticates the heartbeat (PR-A), the fabric gRPC (PR-B/#4357), and now
  the session-sync stream. LOW severity (matches Juniper's own
  unauthenticated direct-cable control-link posture); the acute HIGH lever
  (the full-service fabric gRPC surface) was closed by #4357.
- **Failover.** The handshake happens at connect and a reconnect during
  failover re-handshakes; a keyed↔keyed reconnect completes in
  milliseconds. A dropped handshake closes the connection and the
  accept/connect loops retry (~1s) — it never bricks. MUST pass
  `make test-failover` (the path that keeps TCP alive across failover).
- **Accept-loop isolation + short bound (#4370).** The inbound
  `acceptLoop` runs each connection's setup (handshake + wire-up +
  cold-start bulk sync, inside `handleNewConnection`) in a
  per-connection goroutine — a slow or hung handshake on ONE connection
  can no longer stall accepting the NEXT for up to `syncHandshakeTimeout`
  (previously an active control-link peer could serially block accepts).
  The auth gate is unchanged: the connection is not wired into
  `conn0`/`conn1` and no session frame is read from it until
  `performSyncHandshake` succeeds INSIDE the goroutine; a failed
  handshake closes it. The goroutine is `s.wg`-tracked so `Stop()` waits
  for in-flight setup. The outbound `fabricConnectLoop` stays synchronous
  (a dedicated per-fabric dialer that must not redial mid-handling).
  `syncHandshakeTimeout` is **3s** (was 10s): the keyed↔keyed path is
  sub-millisecond, so the bound only covers a hung/absent peer, and a
  shorter bound keeps a stalled handshake goroutine within the 5s `Stop`
  budget.
- **Atomic install + cold-prime decision (#4962).** Because #4370 made
  `handleNewConnection` per-accept, two same-fabric accepts can race: the
  loser observes the winner's just-installed connection, closes it
  (aborting its in-flight cold-prime bulk), and — under the pre-#4962
  after-unlock `wasDisconnected` read — skipped cold-prime, leaving the
  **surviving** connection un-primed (peer blackholes on the next
  failover). `installConn` now wires the connection into `conn0`/`conn1`
  and computes the cold-prime decision under the **same** `s.mu`
  acquisition, gated on a `needColdPrime` latch (armed on a
  full-disconnect→connect edge, consumed only when a bulk succeeds) so the
  surviving accept **inherits** the outstanding obligation and re-drives
  the bulk. See `docs/session-sync-architecture.md` → "Atomic Install +
  Cold-Prime Decision (#4962)".

## Operating the control-link PSK (#6611)

All three authenticated control channels above — heartbeat (PR-A), fabric
gRPC (#4357) and session sync (#4369) — key off ONE leaf:

```
set chassis cluster authentication-key <key>
```

Each channel deliberately fails **OPEN** when that leaf is absent, which is
what makes a rolling key rollout possible. The cost is that an unkeyed
cluster runs its whole control channel unauthenticated: any host that can
reach the control segment can forge a heartbeat to drive election, call the
allowlisted fabric RPCs (read/clear sessions, cross-node failover), and open
a session-sync connection. Before #6611 every config this repository shipped,
documented and tested was unkeyed, so the enforcing branches were dead code
in practice.

### Where the key is required

`validateClusterAuthKeyStrict`
(`pkg/config/compiler_validate_strict_cluster_auth.go`) rejects a `chassis
cluster` with no key on the **strict** compile path and downgrades to a
`cfg.Warnings` entry on the **tolerant** path (`opts.lenientClusterAuthKey`).
Strict is **not** only the operator commit — it is every caller of
`compileTreeStrict`:

| path | caller | effect of a reject |
|---|---|---|
| operator commit | `Store.Commit` / `CommitCheck` / `CommitConfirmed` | **Inert for traffic.** The active config and the dataplane are untouched; the cluster keeps running while you add the key. |
| **first-boot import** | `daemon.bootstrapFromFile` (`daemon_apply_commit.go`), taken whenever the config DB has no active config (`daemon_run_bringup.go`) | **The node comes up with NO active config** — unattended, no warning. |
| **day-0 validation** | `configstore.CheckText` (`xpfd check-config`) | `xpf-deploy.py` dies; `make_config_drive.py` refuses; the first-boot loader `scripts/image/xpf-day0-config` falls back to the **factory bootstrap**. |
| **autonomous remediation** | `pkg/eventengine` — `store.CommitCheck()` then the daemon's commit closure (`engine.go`) | Every `event-options` `change-configuration` policy **silently fails** until the cluster is keyed. |
| load / peer config-sync | `Store.Load`, `SyncApply` → `compileTreeLenient` | **Warns and boots.** This is the in-place upgrade path. |

So an **in-place upgrade** still boots — that population keeps its
`.configdb` and loads leniently. Note the fourth row applies to exactly
that population: from the moment of upgrade, an unkeyed cluster's
event-driven `change-configuration` remediation stops committing, with no
operator present to see the rejection. "The cluster keeps running" is
true of traffic and the dataplane; it is not true of automation. What is NOT safe is provisioning a node **without** a DB
while the cluster's config is still unkeyed: reimaging or replacing a failed
node, restoring from an archived text config, or building a day-0 drive from
an unkeyed config. A node in that state comes up unconfigured, and a
factory-default node never forms the cluster, so peer config-sync cannot
rescue it. This repository's own `make cluster-deploy` takes that path —
`test/incus/cluster-setup.sh` pushes the text config and then `rm -rf
/etc/xpf/.configdb`.

### Required order

> **Key the RUNNING cluster first. Only then re-provision, reimage, or
> rebuild a day-0 drive.** The reverse order strands the new node.

The keying commit strict-compiles the WHOLE candidate, so on a cluster
whose config has never been strict-validated it can be refused for an
unrelated reason a lenient boot tolerated — a stale typed leaf (#1319), a
node-identity mismatch (#4185), an RA-interval violation (#4525). That is
the same population this gate is aimed at, so expect to fix those first;
the order above is still the right one, it just may not be a single step.

### Generating and distributing the key

Any high-entropy string; 32 bytes of base64 is a good default:

```
openssl rand -base64 32
```

The key must be **identical on both nodes** and must NOT be `${node}`-scoped —
each node signs with it and verifies the peer with the same value, so a
per-node key authenticates nothing and leaves the channel permanently in
dual-accept. Put it in the shared (non-group) `chassis cluster` stanza, as
the reference configs do.

**Provision it out-of-band — do not rely on `configuration-synchronize` to
carry it (#6629).** Config-sync serializes the active config and writes it
over the session-sync stream, which is HMAC-authenticated but **not
encrypted**; during the very first rollout that stream is also still
unauthenticated (see below). Push the key to each node by the same trusted
channel you use for any other secret.

Out-of-band provisioning alone does **not** avoid the exposure. Every
shipped config sets `configuration-synchronize`, and the RG0 primary's
commit calls `pushConfigToPeer`, which sends `Store.ShowActive()` — the RAW
formatted tree, with no `ast_redact.go` pass on that path. So the cleartext
PSK crosses the control segment at step 1 of the rollout below no matter how
you delivered it. To actually avoid it, take config-sync out of the loop for
the duration:

```
delete chassis cluster configuration-synchronize   # see the caveats below
<key both nodes out-of-band, per the rollout below>
set chassis cluster configuration-synchronize      # ONLY once #6629 lands
```

**Two caveats, both load-bearing — read them before running the above.**

*The restore does not restore safely.* An earlier version of this section
claimed the restore commit was safe because it re-synchronises a config both
nodes already hold, so the key is "no longer new information on the wire".
That is wrong: the stream is authenticated but **not encrypted**, and a
passive observer on the control segment reads the cleartext PSK off that
re-sync regardless of whether the peers already know it. Confidentiality is
not a function of who else already has the secret. Until #6629 gives that
path either redaction or transport encryption, **the honest advice is to
leave `configuration-synchronize` off on a keyed cluster** and manage config
on both nodes out-of-band, accepting the operational cost. Restore it only
when #6629 has landed.

*By far the easiest path is to never reach this state.* Provision both
nodes from text with `configuration-synchronize` ABSENT and the key
already set, before the pair carries traffic. Note that the shipped
reference configs (`docs/ha-cluster.conf`, `docs/ha-cluster-userspace.conf`)
DO enable `configuration-synchronize`, and the Incus test harness pushes
them unchanged — so neither is an example of this order; you have to
remove the line from your own config first. On a new build or during a
maintenance window you were taking anyway, this costs nothing.

*On a LIVE pair whose secondary gate is ARMED, the delete cannot be done
without the sync undoing it.* (Everything in this subsection assumes an armed
gate; on the row-2 unarmed node the second delete needs no promotion at all.
That is the #6890 hole, not a supported route — see the Recovery section. This
subsection does not restate the caveat again.)
`configuration-synchronize` is committed from the RG0 primary. Delete it
there and the SECONDARY still has it enabled — so the moment that secondary
is promoted, reconciliation (`daemon_ha.go:444`) sees sync enabled in its
own local config and pushes its COMPLETE active configuration back to the
former primary (`daemon_ha_sync.go:462`), restoring the very line you just
deleted. You cannot simply "delete on both nodes": the second delete
requires a promotion, and the promotion re-adds the first.

There is one safe order you can RELY on for a live pair, and it is a controlled
single-node outage — not a two-command sequence, and NOT a link cut:

```
# 1. On the RG0 primary: delete the line and commit.
delete chassis cluster configuration-synchronize   # commit

# 2. Stop xpfd on that SAME node and leave it down.
systemctl stop xpfd

# 3. Wait for the peer to promote AND for its session-sync to report the
#    peer disconnected. Do not proceed on a timer — wait for the field.
show chassis cluster status          # on the peer: it must be primary, and
#   "Sync link statistics (control-link): Status: Down"   must be present

# 4. On the now-primary peer: delete the line and commit.
delete chassis cluster configuration-synchronize   # commit

# 5. Verify BOTH persistent stores no longer carry it, then restart the
#    stopped node. Sync is absent on both sides, so nothing pushes the
#    line back regardless of which node ends up primary.
systemctl start xpfd
```

Step 2 is what makes this work: with that node's `xpfd` down there is
nobody for the promoted peer's reconciliation to push to, so the deletion
survives the promotion.

Two details worth stating rather than leaving to be discovered. The
restarted node comes back as SECONDARY only in the normal non-preempt
case — with RG0 preemption enabled a returning higher-priority node can
reclaim primary (`election.go`), so expect a failback. It does not matter
for this procedure, because sync is absent on both sides by then, but it
does change what you will see. And the promoted peer may attempt
reconciliation before it has detected the disconnect; that is harmless
here, because config transmission writes directly to the active
connection rather than queueing for replay, the stopped node cannot apply
it, and during teardown it still considers itself RG0 primary and rejects
incoming config.

**Do NOT sever the link instead.** An earlier version of this section
suggested cutting "the session-sync/fabric segment" before promoting.
That is wrong and dangerous. Session and config sync run on the CONTROL
link — the same interface as the heartbeat, port 4785 — and only fall
back to fabric when no control interface is configured
(`daemon_ha_sync.go`). So cutting fabric alone does not stop config sync
in any shipped configuration, and cutting the control segment takes the
heartbeat with it: both nodes stop hearing each other, both declare the
peer dead, and both become primary. That is a dataplane split-brain with
duplicate VIPs, not merely two nodes with independent config authority.
A physical cut also races disconnect detection, so a promotion issued
immediately after it can still find the session established.

Once BOTH nodes have sync disabled, ongoing config management is manual and
paired: treat only the RG0 primary as writable (that is the intent; see the
#6890 caveat above for where the gate is not actually armed), so every change is
a controlled RG0 promotion, an edit, verification on both stores, and a
failback. That
cost is the reason #6629 (redaction or transport encryption for the
config-sync payload) is the real fix, and why this is documented as a
constraint rather than recommended practice.

### Rolling it onto a live unkeyed cluster

**There is no non-disruptive sequence. Keying a live unkeyed cluster costs a
controlled outage on one node.** #5078 removed dual-accept, which was the only
mechanism that made the forward direction seamless, so the operation is now a
special case of the recovery problem rather than a rollout procedure of its own.

**Do not follow a step list from this section.** The preconditions are what
decide whether a given node can be keyed at all, and they are enumerated once —
with their failure modes and their tracking issues — under **"Recovery: no path
is unconditional, and the one you can plan around costs a controlled outage"**
above. Read that enumeration, establish which row your cluster is in, and act on
that row.

Why this section does not restate them: three earlier revisions of the recovery
discussion each replaced a hedge with an absolute, in three different
directions, and each was refuted. A second summary here would be a fourth
attempt at the same mistake, and it would drift from the enumeration the moment
either changed.

The shape of the constraint, so the enumeration reads in context:

- **The keyed side stops accepting the unkeyed peer immediately.** Once one node
  commits the key, `syncAuthDecision` rejects a local-key/peer-unkeyed
  connection unconditionally. There is no first-contact grace — that grace was
  an unauthenticated active bypass, not a compatibility affordance (#5078).
- **So the second node must be keyed while it can still commit.** On an RG0
  secondary whose read-only gate is ARMED, `EnterConfigureSession` returns
  `ErrClusterReadOnly` from every entry point, and the commit that would key it
  is refused. If sync has already dropped, it cannot be reached over the
  fabric either.
- **`configuration-synchronize` does not rescue this**, because the connection
  that would carry the config to the secondary is the one the keyed side is now
  rejecting.

The path you can plan around is **controlled RG0 promotion** (row 3 of the
recovery enumeration): stop `xpfd` on the keyed node so the secondary promotes,
which clears its read-only gate and lets it accept a local commit of the same
key. Every "if" in that row is a real precondition — election eligibility,
event delivery — and they are stated there rather than duplicated here.

For the historical record, dual-accept made the forward direction non-disruptive
by having the keyed node accept the peer's unsigned frames until both sides had
authenticated. **That mechanism no longer exists**; it is described here only so
that a reader encountering the term in older commits or comments knows what it
referred to and that it is gone.

An in-place upgrade (#6628) now promotes an ESTABLISHED connection to
authenticated without a reconnect, so a restart is **not** required for the
legitimate peer once both sides are keyed. That is a separate mechanism from
dual-accept and does not restore a non-disruptive rollout: it upgrades a
connection that is already admitted, and the problem above is a connection that
is being refused.

Session sync fixed a connection's authentication state when the TCP connection
was established (`performSyncHandshake` → `wrapSyncConn`), and committing the
key does **not** restart cluster comms — the restart decision compares only
`clusterTransportKey` (`daemon_apply_tail.go` / `daemon_ha_sync.go`), which
excludes the auth key, deliberately, because that connection is what carries
the key to a read-only secondary. So an already-established stream stayed
unauthenticated indefinitely. The heartbeat and the fabric gRPC listener always
picked the key up immediately (both read the live key per frame / per RPC);
only session sync was connection-scoped.

A commit now triggers an **in-place upgrade** over the established connection
(`sync_auth_upgrade.go`): a three-frame Noise_NNpsk0 exchange promotes it to
authenticated, and re-derives BOTH directional frame keys on a rotation, with no
reconnect. It only ever promotes and never drops, so a peer that cannot
participate is left exactly as it was.

Since #7163 it runs the same construction as the connect handshake, separated by
a phase byte in the prologue, and the role is the LOWER NODE ID rather than the
smaller nonce — a nonce is peer-supplied, and role must not be an
attacker-chosen input to our own key derivation. The higher-id node therefore
cannot open the exchange; when it is the one that becomes keyed first it sends
an `AuthUpgradeRequest` (type 37), which carries no key material and moves no
boundary. The exchange dropped from four frames to three because psk0 tags the
initiator's FIRST message, so the responder authenticates the initiator before
it answers — the whole reason the fourth frame existed. See
`docs/session-sync-architecture.md` for the frame diagram.

A round is NOT replaceable while the peer may have committed to it. A msg1 is 48
bytes of cleartext on the not-yet-sealed stream this mechanism exists to fix,
and its tag covers only the prologue and the initiator's ephemeral, so a
captured Hello re-verifies; answering a replayed one would strand the msg2 the
initiator has already derived from, and drop the connection. The responder
therefore refuses a msg1 while it is awaiting a Confirm, the initiator never
supersedes an incomplete round even for a rotation, and the responder stays
silent rather than prompting in that window. A rotation is not stranded by this:
a Request from the peer disturbs the round, and a round that completes under a
retired key re-triggers itself. A Request carries no MAC, so it is treated as a
hint rather than an instruction — one for a round still outstanding under the
same key re-sends that round's Hello byte for byte instead of minting a new
round, which is what keeps a forged Request from discarding one.

**The residual, and how to close it (#7441).** A HOSTILE stream admitted before
the commit declines the upgrade by staying silent, and a decliner is
indistinguishable from a legitimate peer that is not keyed yet — which is the
rolling-upgrade case the mechanism must not break. The upgrade alone therefore
cannot evict it.

`set chassis cluster strict-session-auth` closes it. While it is set AND this
node holds a control-link key, an established session-sync connection that has
not authenticated within a short grace (`strictSessionAuthGrace`, 10s) is
CLOSED. A legitimate keyed peer reconnects immediately and authenticates
through `performSyncHandshake`; a hostile stream cannot, because
`syncAuthDecision` refuses an unkeyed peer on a fresh connection.

**It is a DECLARATION, not an inference, and that is the whole design.** Three
signals look like the missing discriminator and each fails:

- `HeartbeatPeerAuthSeen()` proves the LEGITIMATE peer holds the key on a
  channel that reads it live — necessary, but not sufficient. A keyed
  legitimate peer on an OLDER, pre-#6628 build also cannot answer the upgrade,
  so dropping on this signal alone breaks a rolling upgrade.
- The peer's `syncMsgPeerCapabilities` advertisement (#6650) would say whether
  the peer is new enough to answer — except a hostile peer simply WITHHOLDS
  it, and withholding then buys immunity. Using a peer-supplied value as the
  arming input hands the attacker the switch.
- Time alone is what #5078 shipped and removed.

What is left is the operator, who knows the one thing neither node can observe:
whether the cluster is homogeneous.

**Operator contract.** Set it on each node, once BOTH nodes are keyed and BOTH
are on a #6628-capable build. It is **node-local**: config-sync never carries
it, in either direction, so you must set it on both nodes yourself. That is not
a convenience gap — an unauthenticated stream's frames reach
`handleConfigPayload` (`readAuthed()` gates trailer VERIFICATION only) and
`handleConfigSync` refuses a push only on the RG0 primary, so a synced flag
would be clearable by the very connection it exists to evict.

**If you set it while the peer cannot answer**, that peer's session sync is
dropped and re-established in a loop. The symptom is a rising
`StrictAuthEvictions` counter with sessions not converging; the fix is to
delete the leaf on this node, or finish upgrading the peer. Nothing else
breaks — VRRP, heartbeat and failover are on a different channel.

**Crash-loop behaviour: nothing is persisted, by design.** There is no deadline
to persist, because the decision is recomputed from committed config on every
evaluation, and lapsing anything fails SAFE (the connection is dropped, and a
legitimate peer is re-admitted on reconnect). This is what #5078's window could
not do: it failed OPEN on lapse, so its deadline had to be durable.

If you have reason to believe the control segment was hostile before you keyed
it and you have NOT set `strict-session-auth`, restarting `xpfd` still evicts
the stream.

Confirm the posture with `show chassis cluster statistics`, whose
`Authentication:` line (`controlLinkAuthStatus`) reads
`engaged (peer authenticated; unauthenticated frames rejected)` once both
nodes are keyed — `dual-accept (...)` means the channel is still
unauthenticated in practice. Note this line reflects the heartbeat/fabric
posture; it does not tell you whether an existing session-sync connection
predates the key.

**Rolling BACK is not symmetric.** `peerAuthSeen` is sticky in memory and
clears only on an **xpfd restart** — since #5086 it lives on the `Manager`,
so restarting the heartbeat (VRF rebind, comms restart) no longer clears it
— so a node that has seen its peer authenticate will
reject that peer's unsigned heartbeats. Returning one node to an unkeyed
config or an older binary while the other stays armed produces the same
split-brain described under rotation.

### Rotation

Rotation is a **rolling operation** since #6630. It was a planned outage
before, and the reason is worth keeping in view because it is what the
mechanism below is shaped around.

With a single key, the moment one node is committed to the new one each end
receives a present-but-invalid HMAC from the other. `admitFrame` rejects those
frames **without refreshing `lastSeen`** (`heartbeat.go`), so neither node
refreshes peer liveness: after `heartbeat-interval × heartbeat-threshold` —
200 ms × 5 = **~1 s** at the SHIPPED cluster settings, 100 ms × 5 = **~500 ms**
at the code defaults (`DefaultHeartbeatInterval`) — **both** nodes declare the
peer dead and **both** take over their redundancy groups: dual-master with
duplicate VIPs on the wire for the whole window between the two commits.

The workaround an earlier revision of this document gave — clear both keys,
then set the new one — does not work either. `validateClusterAuthKeyStrict`
(#6611) expressly refuses to commit a cluster with no key, so that path is
rejected by the very gate that requires the key.

#### The overlap

```
set chassis cluster additional-authentication-key <key>
```

A second key this node **ACCEPTS** and never **SIGNS** with. Because signing is
unchanged, a rotation never has two signers, and the commits can therefore be
separated in time. It does **not** satisfy #6611 on its own: a cluster whose
only key is this one signs nothing and is refused at commit with a message
saying so.

An overlap is **forced, not preferred**. The two nodes have no channel to agree
a cutover instant on that does not itself depend on the key being rotated, and
under the eventual posture (see "The three-way incompatibility") there is not
even a config-sync push to carry a coordinated plan. Accepting the other key
for an operator-bounded window is the only rotation that keeps liveness.

Both authenticated control surfaces widen together — the heartbeat
(`admitFrame`) and the fabric gRPC listener (`checkFabricAuth`). Widening only
one would turn a rotation from "no outage" into "no outage on the heartbeat,
`Unauthenticated` on every peer-proxied RPC", which is worse for being harder
to see. **Session sync does not widen**: its authentication is fixed per
connection at handshake time, which is #6628's territory, not this one.

#### Procedure — rotate A to B

No maintenance window. Liveness is never lost at any step; each is a state the
cluster can sit in indefinitely.

1. **node0** — `set chassis cluster additional-authentication-key B`
   *(signs A, accepts A+B)*
2. **node1** — the same *(signs A, accepts A+B)*
3. **node0** — `set chassis cluster authentication-key B` and
   `set chassis cluster additional-authentication-key A`
   *(signs B, accepts B+A)*
4. **node1** — the same *(signs B, accepts B+A)*
5. **both** — `delete chassis cluster additional-authentication-key`
   *(signs B, accepts B — the retired key stops authenticating)*

Step 3 is the only one where the two nodes hold different **signing** keys, and
it is the one the overlap carries. Steps 1, 2 and 4 would survive without it;
they exist to reach step 3 safely.

Step 5 is the **finalize**, and it is an operator commit rather than a timer:
the overlap ends when the operator says so and can never lapse into a second
permanent key. `TestPSKRotationFinalizeRejectsTheRetiredKey6630` pins that the
retired key stops authenticating.

Do not skip step 2. Going straight from 1 to 3 puts node1 — which has not
opened its window — in front of a B-signed frame it cannot verify, which is the
outage this replaces.

#### Knowing when it is safe to finalize

```
Authentication:             engaged (peer authenticated; unauthenticated frames rejected)
Key rotation:               in progress (signing 4f2a9c31, also accepting 8b70de55);
                            peer is signing 4f2a9c31 — safe to finalize:
                            `delete chassis cluster additional-authentication-key`
```

The `Key rotation:` line appears in `show chassis cluster statistics` **only**
while an additional key is configured. It renders short key **IDs**, never
keys — an id is `HMAC-SHA256(key, domain tag)` truncated to 32 bits
(`controlLinkKeyID`), derivable identically on both nodes with no exchange, so
the operator can compare a `show` on each node.

It reports three states, and the distinction matters because acting on the
wrong one reopens the dual-master window:

| Line says | Meaning |
|---|---|
| `peer is signing <signing-id> — safe to finalize` | the peer has moved; step 5 is safe |
| `peer is still signing <other-id> — do NOT finalize` | the peer is still on the retired key |
| `peer key UNKNOWN — no authenticated peer frame seen` | usually the peer is down; **not** the same as "not safe" |

"Both configs say B" is a statement about two files. "The peer is currently
SIGNING with B" is a statement about the running system, and only the second
makes retiring the old key safe. The value tracks the **latest** verified
frame, not a high-water mark, so a peer that rolls back to the old key makes
finalize unsafe again rather than staying green.

#### Notes

- Restarting `xpfd` is still required to clear the sticky `peerAuthSeen` if you
  are rolling *back* to an unkeyed config — see "Rolling BACK is not
  symmetric" above. A forward rotation between two real keys needs no restart.
- Rotation remains the **anti-replay capture-invalidation** step (below), and
  making it rolling does not change that: after step 5 the retired key no
  longer verifies anything.
- **No key id goes on the wire.** #6630 asked for one so a receiver could pick
  the key to verify against instead of trying both. Trying both is two HMACs
  over a ~52-byte frame at 5 Hz, and a wire change on the heartbeat is a
  mixed-version hazard on the one channel whose failure mode is dual-master.
  The property the id was for — "can the operator tell whether the peer has
  moved?" — is delivered by recording which accepted key last verified a peer
  frame and rendering its id above. Same answer, no new bytes on the wire.

> [!IMPORTANT]
> **Rotate the PSK after upgrading both nodes to a #6169-capable build.** This
> is a REQUIRED post-upgrade step, not a footnote. Every capture an on-link
> sniffer took before the upgrade was signed with the OLD key, so rotation is
> the only thing that retires an attacker's existing archive — no code change
> can retroactively invalidate frames they already hold. The mechanism is
> `verifyHeartbeatMAC(frame, key)`, which uses the LIVE key: after a rotation
> every pre-upgrade capture fails `macOK` and is discarded before it reaches
> any epoch logic at all.
>
> **This step is what makes the accepted restart residual acceptable.** The
> downgrade latch (`epochSeen`) is process-scoped, so a full daemon restart on
> the surviving node clears it. But do NOT read that as "while the genuine peer
> is absent nothing re-arms it" — an earlier revision of this paragraph said
> exactly that and it is false, as residual 5 below records. A single ARCHIVED
> epoch-bearing frame, captured while the peer still ran an epoch-capable build,
> re-arms the latch on its own: after the restart `highEpoch` is 0, so the replay
> passes the absolute band, the forward bound and the empty ring, and arms
> `epochSeen`. One replay per restart holds the rolled-back peer out
> indefinitely.
>
> That is precisely why rotation comes FIRST. Rotation invalidates the archive,
> so there is nothing left to replay into the window. Skipping it leaves the
> residual live, and restarting without rotating leaves the latch armed *through*
> a later rotation — costing a second restart. The residual was not priced as
> "narrow" on the assumption that nobody would skip the rotation.
>
> **How to tell whether you are still exposed:** `show chassis cluster
> information` / `statistics` print `Heartbeats without epoch:` in the
> `Control link statistics:` block. If it is non-zero and still climbing after
> both nodes are upgraded, this node is still accepting epoch-less frames —
> either a node is genuinely on an older build, or someone is replaying
> captures — and the line carries an inline note saying so. Once an accepted
> epoch-bearing frame arms the latch, the inline note flips to "downgrade latch
> armed; count is historical" and the epoch-less count stops climbing.
>
> That note reports the LATCH, not current enforcement, and the wording is
> deliberate. `heartbeatAuthDecision` dual-accepts everything when no local key
> is configured, and `UpdateConfig` clears the live key without resetting
> `hbAuth` — so a cluster that added the key under `commit confirmed`, armed the
> latch, then let the confirmation time out back to an unkeyed config is left
> with the latch armed and epoch-less frames admitted anyway. An armed latch
> therefore means "this node has seen the peer emit an epoch", not "this node is
> refusing epoch-less frames right now".
>
> **The latch only enforces while a PSK is configured, so read it together with
> the `Authentication:` line** in `show chassis cluster control-plane
> statistics`. `engaged (peer authenticated; unauthenticated frames rejected)`
> means the latch is being applied; `dual-accept (no control-link key
> configured)` means it is not, whatever the note says.
>
> `Epoch downgrades rejected:` is a SEPARATE signal and does **not** start
> counting when the latch arms — it stays at 0 until some later epoch-less
> frame actually arrives and is refused, which on a healthy upgraded cluster
> may never happen. Read it as "something is still sending epoch-less frames
> and being turned away" (a peer left behind, a rollback, or a replay), not as
> a confirmation that the latch is armed. The inline note is what reports the
> latch.

Rotation is also the **anti-replay capture-invalidation** step. Every capture
an on-link sniffer took BEFORE the rotation was signed under the old key, so
after a rotation none of it verifies. It does **not** retire a capture taken
after the rotation: that frame was signed with the key still in force and still
verifies (`TestRotationDoesNotRetirePostRotationCaptures_6669`). Rotation is the
recovery step for an existing archive, not a prophylactic against a new one.
The boot-epoch marker is key-derived (`HMAC(PSK, "xpf-ha-boot-epoch-v1")[:8]`),
so it changes with the key automatically — no separate rollout step. The
restart in step 3 also clears each node's in-memory epoch floor and latch; both
re-arm from the peer's next epoch-bearing heartbeat, within one heartbeat
interval.

Do **not** try to "return to dual-accept" by clearing the key first: an
unkeyed `chassis cluster` is exactly what the commit gate rejects, so that
path does not exist. Tracked as **#6630**.

### Key strength

The commit gate is an **emptiness floor, not an entropy floor**: it rejects an
absent or whitespace-only key (whitespace would satisfy the runtime's
`len(key) > 0` test while being no key at all), but a one-character key
passes. Strength is a continuum, so `ClusterAuthKeyStrengthWarnings` reports
it as a **warning** on both paths rather than rejecting — hard-rejecting a
short key would create a new brick class, including via the unattended
`bootstrapFromFile` path, for an operator who already configured
authentication. It warns below `MinAdvisedControlLinkKeyLen` (16 characters)
and when the key looks like one of this repository's published placeholders.

Trimming makes the gate STRICTER than the runtime, not identical to it, and
on the tolerant path that difference is observable: a leniently-loaded
`authentication-key "   "` warns "no authentication-key configured" at boot
while the runtime treats the untrimmed three-space value as a real key, so
`show chassis cluster statistics` can report `engaged` once the peer
authenticates with the same three spaces. Pathological and pre-existing —
noted so the two surfaces are not read as contradicting each other.

### Shipped configs

`docs/ha-cluster.conf`, `docs/ha-cluster-loss.conf`,
`docs/ha-cluster-userspace.conf`, `test/incus/xpf-cluster-fw{0,1}.conf` and
`examples/deploy/ha-pair.conf` all carry a key, so the HA smoke cluster
exercises the ENFORCING branch rather than the `keyConfigured == false`
shortcut. Those values are **published in a public repository**: a config
copied from them satisfies the gate while remaining trivially forgeable by
anyone who has read the repo. They are marked `CHANGE-ME` and trip the
placeholder warning above. Replace them before any real deployment.
`TestShippedClusterConfigsAreKeyed_6611` / `...UseOneKeyPerCluster_6611`
(`pkg/config`) lock the keyed and one-key-per-cluster properties;
`TestBootstrapFromFileRejectsUnkeyedCluster_6611` (`pkg/daemon`) and
`TestCheckTextRejectsUnkeyedCluster_6611` (`pkg/configstore`) pin the two
unattended strict paths.

The `authentication-key` leaf is `config.Secret`-typed and is redacted in the
ordinary show/log/JSON render paths (`ast_redact.go`), so it is not exposed to
routine operator output or diagnostics. That is not an absolute guarantee: a
sufficiently privileged CLI class can still render cleartext configuration.
Keep the authoritative copy in your own secret store.

Config sync used to transmit it in the clear as well (#6629). It no longer
does against a peer of the same vintage — see below — but the qualifier
matters.

### Config sync and the PSK (#6629)

Config sync ships the ACTIVE TREE rendered unredacted, so the PSK travelled
inside a `syncMsgConfig` payload, on the link it authenticates, at the one
moment that link is guaranteed unauthenticated: session-sync auth is fixed per
connection at handshake time, and committing a key does not restart cluster
comms, so the carrying connection is by construction one handshaked while both
ends were unkeyed. A passive observer learned the key as it was introduced and
could forge every subsequent HMAC on the link. The rollout defeated itself on
first use.

The payload is now sealed under a key derived from a fresh ephemeral X25519
exchange performed on every connection (`syncMsgConfigKeyExchange` /
`syncMsgConfigEncrypted`; mechanism and wire format in
`docs/session-sync-architecture.md` -> "Config-Payload Confidentiality").

Read the scope literally:

- It defeats a PASSIVE observer, including one holding a full historical
  capture — the keypair is per connection, so there is forward secrecy across
  reconnects.
- It does NOT defeat an ACTIVE man-in-the-middle. The exchange on an unkeyed
  link is unauthenticated because there is nothing yet to authenticate it
  with. An active attacker on an unkeyed control segment can already drive
  election, call the allowlisted fabric RPCs and inject sessions — that is the
  argument for keying at all — so nothing new is conceded, but do not read
  this as a confidential channel.
- Against a peer that predates #6629 the push falls back to CLEARTEXT, with a
  warning. During a mixed-version window the old behaviour applies in full.
- **A capture taken before the upgrade is not retired by the upgrade.** Rotate
  the PSK after both nodes are on a #6629-capable build, for the same reason
  the #6169 note above gives: no code change invalidates frames an attacker
  already holds.

### The three-way incompatibility (#6628 / #6629 / #6630)

Three shipped positions cannot all hold, and every fix in this area has to
declare which one it moves:

1. **#6629**: the PSK must not cross the control link in cleartext.
2. **`TestAuthKeyChangeDoesNotRestartClusterComms_5078`** pins the exact
   opposite of #6628's fix, and its failure message states the reason —
   "committing it would restart cluster comms and drop the very connection
   that must carry the key to the read-only secondary."
3. **`sync_auth.go`'s `syncAuthDecision` comment**: an RG0 secondary whose
   read-only gate is armed returns `ErrClusterReadOnly` from
   `EnterConfigureSession`, so config-sync is that node's ONLY writer. In-band
   carriage of the PSK is not incidental — it is the documented live-keying
   procedure.

Consequences to hold on to:

- **#6628 landed alone bricks the live-keying rollout.** The instant the
  primary commits the key the connection drops, re-handshakes, and
  `syncAuthDecision(keyConfigured=true, peerKeyed=false)` REJECTS the
  still-unkeyed secondary — which can then never be keyed at all, because it
  is read-only. A self-inflicted permanent partition.
- **The eventual posture** is that the PSK becomes provisioning-time
  node-local state that config-sync neither carries nor overwrites (the
  per-node day-0 config drive already provisions `xpf.conf` alongside
  `node-id`, and `sync_auth.go` already recommends "keying at provisioning,
  before either node seats as secondary"). #5078's pin is inverted as PART of
  that change, never on its own.
- **#6630's rotation is then FORCED, not preferred.** With no in-band
  coordination channel left, accepting the previous key for a bounded overlap
  window is the only rotation that keeps heartbeat liveness.
- Payload encryption (#6629, above) deliberately does NOT untie this knot. It
  closes the disclosure without touching carriage, so the three can be
  resolved as one design later rather than under time pressure.

## IPsec SA sync

Active IKE/child-SA connection names ride the session-sync channel so the
standby can re-initiate the primary's tunnels on takeover:

- **Send** — `syncIPsecSAPeriodic` (`pkg/daemon/daemon_ha.go`) runs on the
  RG0-primary and, every 30s, reads the active set from
  `ipsec.ActiveConnectionNames()` (live `swanctl --list-sas`) and advertises it
  via `SessionSync.QueueIPsecSA` (wire type `syncMsgIPsecSA`,
  `encode/decodeIPsecSAPayload`).
- **Hold** — the standby stores the peer's set wholesale in `peerIPsecSAs`
  (`sync_conn.go` overwrites, not merges), readable via `PeerIPsecSAs()`.
- **Full-set ordering (#5706)** — because the set is REPLACED wholesale and both
  fabric `receiveLoop`s run concurrently, a full-set reordered across the
  redundant streams could overwrite a newer set with an older one. Each push now
  carries a trailing `(incarnation, seq)` (`appendIPsecFullSetSeq`, which inserts
  a `\n` delimiter before the trailer so an old newline-decoder never fuses the
  trailer onto the last SA name); the receiver admits only a strictly-newer pair
  per stream (`ipsecRecvSeq`, a `fullSetSeqGuard`), strips the delimiter
  (`stripIPsecFullSetDelim`), and drops a stale reorder (`IPsecSAStaleIgnored`).
  The guard is reset on a peer bulk re-prime (`resetRecvGen`) so an OS-rebooted
  peer's fresh set (lower monotonic incarnation) is re-accepted. A legacy peer
  sends no trailer → `(0,0)` → accept-always (mixed-version compat). See
  `docs/sync-protocol.md` "Full-set state-sync ordering (#5706)".
- **Re-initiate on takeover** — `reinitiateIPsecSAs` reads `PeerIPsecSAs()` and
  `InitiateConnection`s each name when this node becomes RG0-primary.
- **Empty-set / tunnel-down handling (#4385)** — a NON-EMPTY set is advertised
  every tick (a heartbeat re-push — the only mechanism that seeds a freshly
  reconnected/restarted standby, so it must keep pushing even when unchanged).
  An EMPTY set is advertised exactly ONCE, on the drop-to-zero transition from a
  previously non-empty set — a tunnel was administratively downed or all its SAs
  were torn down — so the standby CLEARS its stale `peerIPsecSAs` instead of
  resurrecting the tunnel on takeover. A steady empty set, INCLUDING a node that
  never brought an SA up, is never advertised (no empty-heartbeat churn; the
  standby's default set is already empty). The decision is
  `ipsecSASyncAdvertise` (goroutine-local `lastFP` fingerprint, empty string =
  last advertised set was empty / nothing advertised yet). Before #4385 the push
  was guarded by `if len(names) > 0`, so a drop-to-zero was never advertised and
  the standby resurrected the downed tunnel on failover. Mirrors the DHCP
  `maybePushFamily` change-detect precedent below.
- **Reconnect robustness (#4385)** — the one-shot empty push must survive a
  disconnect gap, so two guards back it:
  - **Confirmed-send retry.** `QueueIPsecSA` returns whether the frame reached an
    ACTIVE conn; `ipsecSANextFP` advances `lastFP` ONLY on a confirmed send. An
    empty advertisement that no-ops on a nil/dropped conn (a drop-to-zero landing
    during a reconnect gap) leaves `lastFP` non-empty, so it RETRIES next tick
    instead of being silently marked sent — without this, `lastFP` would advance
    to empty and the empty would never be re-advertised, stranding the standby's
    stale set.
  - **Peer-connect re-advertise.** `OnPeerConnected` nudges `ipsecSANudgeCh`
    (`nudgeIPsecSASync`), and `syncIPsecSAPeriodic` handles it with a FORCED
    advertise (`advertiseIPsecSAOnce(force=true)` -> `ipsecSASyncAdvertise` force
    branch) of the current set, empty or not. A reconnected standby that missed
    the one-shot empty, or a same-process standby that retained its peer set
    across a blip, converges immediately (empty -> clears; non-empty ->
    re-seeds) rather than waiting up to the 30s tick. Mirrors the DHCP
    peer-connect `nudgeDHCPLeaseSync` (#2239 Q7).

  Note: `peerIPsecSAs` is deliberately NOT cleared on disconnect — a real
  primary death (the standby never reconnects) must leave the last-known set in
  place for `reinitiateIPsecSAs` to re-initiate on takeover. Convergence to an
  empty/updated set is driven by the primary re-advertising, not by the standby
  self-clearing.

## DHCP-server lease sync (#2239)

### Peer-fence acknowledgement (#7147)

`peer-fencing disable-rg-confirmed` gates takeover on a peer-confirmed fence.
The mechanism lives in `sync_fence_ack_7147.go` (wire + waiter) and
`fence_confirm_7147.go` (policy); `docs/ha-failover-status.md` carries the
operator-facing table.

- **Wire** — one additive message type `syncMsgFenceAck = 35` carries
  `{seq u64, status u8, rgs_fenced u16, rgs_total u16}` LE. `syncMsgFence`
  gains an optional 8-byte sequence; seq 0 is RESERVED and means "no ack
  requested", which is what a pre-#7147 sender's empty payload decodes to. A
  capability bit rides the trailing byte of `syncMsgPeerCapabilities` (#6650),
  which is why `sendCapabilities` is now unconditional — see its comment.
  No `SessionSyncWireVersion` / `CurrentHAProtocolVersion` bump, for the same
  reason as #2239 and #6650 below: `MinCompatHAProtocolVersion ==
  CurrentHAProtocolVersion`, so the accepted window is a single point and a
  bump would make `GateMixedBaseSwap` refuse the rolling upgrade.
- **The ack means peer-CONFIRMED, not received.** It is written only after the
  receiver's `fenceAllRedundancyGroups` returns, and reports what that
  achieved. The decoder REFUSES a short frame rather than zero-filling it:
  status 0 is `FenceAckOK`, so a lenient decode would turn fabric corruption
  into a fabricated confirmation.
- **It always fails open.** No connection, no capability, write error, timeout,
  or a negative ack all proceed with the takeover, each recorded to
  `EventFence` with its reason. `SendFenceAwait` returns immediately when there
  is no active connection, so the ordinary dead-peer takeover pays nothing.
- **It REDUCES the split-brain window; it does not eliminate it.** The residual
  is a partition where the sync socket is live but blackholed — TCP has not
  timed out, so the fence is written and no ack returns, and after the bound
  this node takes over while the peer may still be forwarding. Failing CLOSED
  instead would be worse for an appliance (a partition that never resolves
  leaves nobody forwarding), so this is a deliberate trade. The policy NAME
  overclaims; `docs/ha-failover-status.md` states the residual, and the
  `EventFence` line is the only surface that distinguishes a confirmed fence
  from a fail-open — the configured action renders identically either way.

DHCP-server (Kea) leases ride the SAME session-sync channel and follow the
IPsec-SA-sync precedent (`QueueIPsecSA` / `peerIPsecSAs` /
`reinitiateIPsecSAs`), not the Kea native HA hook and not a shared DB. The
mechanism (PATH C of `docs/research/2239-dhcp-ha-lease-sync/plan.md`):

- **Wire** — two additive message types `syncMsgDHCPLeaseV4 = 25` /
  `syncMsgDHCPLeaseV6 = 26` carry a full-set push of the active leases the
  sender serves for a family. `encode/decodeDHCPLeasePayload` (`sync_protocol.go`)
  frame a 4-byte count + length-prefixed, length-GATED per-lease records
  (the #2170 trailing-field discipline: a newer peer's extra fields are
  ignored, a legacy/truncated record zero-fills absent fields, a
  short stream stops at the last complete record). The types are above the
  legacy set so a peer that predates the feature hits the `default` receive
  case and ignores them — no `CurrentHAProtocolVersion` bump (the change is
  additive AND config-knob-gated, so bumping would falsely block session sync
  across a mixed-base pair). Each per-lease string field (address, hwaddr,
  clientid, DUID, leasetype, hostname) is `uint16`-length-prefixed, so the
  writer FAILS CLOSED on a field longer than 65535 bytes: `putLeaseString` /
  `encodeOneLease` return an error rather than let `uint16(len)` silently narrow
  and misframe the peer's decode, and `encodeDHCPLeasePayload` DROPS that one
  lease (with a warning; the count stays consistent) so the surviving leases
  still round-trip — a >64 KiB field is defensive-only, real DHCP identifiers
  are far below it (#4892). The wire format is unchanged; the decoder
  (`getLeaseString`) is untouched — the writer just never emits an oversized
  field.
- **Full-set ordering (#5706)** — like IPsec SA sync, each v4/v6 lease push is a
  wholesale REPLACE, so a reorder across the two concurrent fabric `receiveLoop`s
  could regress the held set. `QueueDHCPLeases` appends a per-family
  `(incarnation, seq)` trailer (`appendFullSetSeq`, INDEPENDENT `dhcpV4SeqCounter`
  / `dhcpV6SeqCounter`), and the receiver admits only a strictly-newer pair per
  family (`dhcpV4RecvSeq` / `dhcpV6RecvSeq`), dropping a stale reorder
  (`DHCPLeasesStaleIgnored`). An OLD receiver reads exactly its record count and
  IGNORES the trailer (clean backward compat); a legacy sender's `(0,0)` is
  accept-always. See `docs/sync-protocol.md` "Full-set state-sync ordering
  (#5706)".
- **Clock invariant** — each lease carries REMAINING LIFETIME, never an
  absolute wall-clock expiry (the channel only syncs a MONOTONIC offset). The
  promoting node re-anchors to its LOCAL clock at seed (`expire = now + remaining`),
  so peer wall-clock skew can never mis-age a synced lease — the structural
  fix for the <60s hazard the Kea native HA hook inherits.
- **Send** — `SessionSync.QueueDHCPLeases(family, leases)` (`sync.go`), driven
  by the RG-MASTER push loop in `pkg/daemon/daemon_dhcp_lease_sync.go`
  (`syncDHCPLeasesPeriodic`): a 30s full-set heartbeat (so a restarted standby
  is never empty) + a 2s on-grant change-detect (push only when the set
  changed, bounding the duplicate-allocation window). Fail-open: a send error
  is logged + counted, never blocks lease granting.
- **Hold** — the BACKUP stores the peer's set in `peerDHCPLeases{4,6}` (the
  `peerIPsecSAs` precedent), accessible via `PeerDHCPLeases{4,6}()`. Its Kea
  stays STOPPED (`clearRethServicesForRG` is UNCHANGED) — VRRP/RG remains the
  sole who-serves arbiter.
- **Seed on takeover** — `pkg/daemon` pre-seeds the held leases into the Kea
  memfile BEFORE Kea start (fully closes the dup-alloc window) AND
  `lease{4,6}-add`s them over the Kea control socket after start (idempotent
  backstop, `RecordDHCPLeasesSeeded`). The Kea read/write side lives in
  `pkg/dhcpserver/lease_sync.go`.
- **Observability** — `SyncStats.DHCPLeases{Sent,Received,Seeded}` surfaced in
  `show chassis cluster statistics` (`status.go`).

Gated end-to-end on `set chassis cluster dhcp-lease-synchronization`
(`config.ClusterConfig.DHCPLeaseSync`); standalone / knob-off renders the Kea
config bit-identical to pre-#2239 (no control-socket, no hook).

## A clamped monitor weight is visible to the operator (#6589)

An out-of-range `interface-monitor ... weight` is bounded to `[0,255]` by
`ClampInterfaceMonitorWeight`. That clamp is reachable ONLY from a
persisted config or an HA config-sync push — the strict commit gate
rejects an out-of-range weight outright — which is exactly the
population an operator cannot see by re-reading what they typed.

**The clamp direction is settled and is not the defect.** 0 is retained
(not 255) because it is an already-legal, operator-reachable state: an
`interface-monitor` with no `weight` token compiles to exactly 0,
meaning "monitor this, contribute no debt". Clamping invalid input onto
an existing semantic is less surprising than clamping it onto
"maximally fatal", and under clamp-to-255 a typo'd `-100` arriving over
config-sync would make the RECEIVING node resign its redundancy group
the moment that link flaps — turning config-sync into a remote HA
denial of service.

What was wrong is that the clamp was INVISIBLE, and in a specific way:
every renderer already called the clamp and discarded the signal —
`w, _ := ...` — so it printed a plausible 0 or 255 indistinguishable
from an operator-authored one. A diagnostic that fails to a value that
looks healthy. A monitor clamped to 0 owes no election debt, so its RG
does not demote when that link fails and the operator finds out during
a failover that does not happen.

`InterfaceMonitorInfo` (and `routing.InterfaceMonitorStatus`, which
carries the LIVE path both renderers take — annotating only the
config-only fallback would have left the common case silent) now carry
`ConfiguredWeight` + `Clamped`, and `show chassis cluster interfaces`
renders `N (cfg M)` plus a note stating the consequence. Zero values
mean "not clamped", so a producer that does not set them renders
exactly as before.

**The ip-monitoring half was worse than filed.** The interface-monitor
class at least reaches journald once per config apply
(`reconcileMonitorDebtsLocked`). The IP class reached NOTHING:
`ipTargetWeight` and the global-threshold aggregate both discarded the
signal and no site anywhere logged it, so an out-of-range ip-monitoring
weight was invisible including in the log. `Monitor.ClampedIPMonitorWeights`
reports it and `FormatIPMonitoringStatus` renders it. An unset per-target
weight is deliberately NOT reported: it inherits the global one, which is
reported on its own line, and reporting it twice would show a per-target
clamp the operator never configured.

Note on the `SetMonitorWeight` chokepoint: its own clamp-and-warn is
documented as effectively unreachable, because every producer bounds the
weight before it gets there. That is deliberate defense-in-depth and the
code says so — but it does mean a missing warning there must never be
read as "no out-of-range weight was configured".

## Interface-monitor link-state detection

`Monitor` (`monitor.go`) is the live carrier-detection loop: a 1-second
ticker polls each configured `interface-monitor`, dampens transitions,
and calls `SetMonitorWeight` so a redundancy group is demoted when a
monitored uplink goes down. The whole point of interface-monitoring is to
catch carrier loss (cable pulled / peer link down) and fail over.

Link health is therefore decided from the kernel **operational** state
(`IFLA_OPERSTATE`) via the exported `LinkAttrsUp`, **not** the
administrative `IFF_UP` flag. xpfd admin-ups every managed interface, so
`IFF_UP` is the normal steady state and stays set even after carrier loss
— using it (or OR-ing it in) would report a cable-pulled link as UP and
suppress failover (#2070). The rule is: `OperUp` → up; `OperUnknown` →
fall back to the admin flag (virtual devices and 802.1Q VLAN
sub-interfaces that report no independent carrier state); `OperDown` /
`OperLowerLayerDown` / anything else → down. This mirrors
`pkg/vrrp.linkAttrsUp`, the canonical link-state read used by VRRP
track-interface detection. `pkg/routing/monitor.go` (the display-side
`InterfaceMonitorStatus` path) carries its own identical copy.

**Missing local link = down (#5080).** A `LinkByName` failure for a
monitor on the LOCAL FPC slot means the configured member link is absent
(cold boot before the NIC appears, or a delete/recreate between polls).
`pollInterfaceMonitors` feeds that absence through the same dampening
machinery as a carrier-down link — it must NOT be silently skipped.
Skipping fails open: an already-primary node keeps effective weight 255
and stays primary while its data link is missing, blackholing traffic. A
monitor on a PEER's slot (`SlotToNodeID(slot) != NodeID`) is still
skipped — the peer publishes that interface's status over heartbeat.

**Reconcile monitor debt on config change (#5080).** Effective RG weight
must always derive from the COMPLETE current desired monitor set. On
`UpdateConfig` the manager runs `reconcileMonitorDebtsLocked`: it builds
the desired `(rgID, iface)→weight` map from the new config, clears the
installed debt (`monitorWeights` + each RG's `MonitorFails`) for any
monitor that was REMOVED or whose interface CHANGED, re-derives the debt
for a still-failed monitor whose configured weight changed, then
recomputes each affected RG's weight — all before the election runs. In
tandem, `Monitor.UpdateGroups` drops the dampening `ifaceState` for
monitors no longer desired. Without this, `UpdateConfig` only swapped the
desired slice, so a debt installed for a monitor the operator later
removed/changed persisted and stranded a healthy node secondary forever.
`UpdateGroups` deliberately does not call the locking `SetMonitorWeight`
(it runs under the manager lock already held by `UpdateConfig`); the
manager-side clear happens directly in `reconcileMonitorDebtsLocked`.

**Monitor map locking and the `m.mu -> mon.mu` order (#6550).** The poll
goroutine and `UpdateGroups` share four maps — `ifaceState`, `ipState`,
`ipDebts`, `ipThresholdState`. `UpdateGroups` deletes from all four under
`mon.mu`; the poll cycle used to write all four with no lock at all, which
is a Go RUNTIME FATAL (`concurrent map read and map write`), not a
tolerable race, and it is reachable from an ordinary commit — with
config-sync, on both nodes.

The repair cannot be one lock around the whole apply phase. The lock order
in this package is **`m.mu` -> `mon.mu`**: `Manager.UpdateConfig` holds
`m.mu` across its whole body and calls `Monitor.UpdateGroups`, which takes
`mon.mu`. The poll path calls `mgr.SetMonitorWeight` / `mgr.RecordEvent`,
which take `m.mu`. Holding `mon.mu` across those callbacks inverts the
order and deadlocks a commit against a poll — trading a probabilistic
fatal for a deterministic hang.

So each mutation site takes `mon.mu` for the map access and the dampening
update it feeds, and releases it before calling the manager.
`reconcileRGIPDebts` drives its whole bookkeeping to the new value under
the lock, collects the resulting weight changes into a local
`[]ipDebtAction`, drops the lock, and only then replays them (removals
first, then installs — the pre-#6550 emission order). `desiredRGIPDebts`
therefore requires `mon.mu` held. `Monitor.Stop` is unaffected: it drops
`mon.mu` before `wg.Wait()`, so a poll blocked on the lock cannot wedge a
teardown.

Two probes pin this, both in `monitor_poll_update_race_6550_test.go`: a
race probe (poll cycles bounded, `UpdateGroups` looped, ratio logged) and a
deterministic lock-order probe that lands an `UpdateGroups` on another
goroutine exactly at a manager callback and requires it to complete. Both
assert only under `-race` or a deadlock, so a third test reads the
Makefile and requires `test-race-dp` to keep its `./pkg/cluster/` leg —
before #6550 no make target raced this package at all, so these were races
CI had no path to rather than races CI had missed.

`reconcileMonitorDebtsLocked` reconciles INTERFACE-monitor debt ONLY.
`monitorWeights` + `MonitorFails` are a SHARED structure that also holds
IP-MONITORING debts (installed by `SetMonitorWeight` from the ip-monitor
path under the per-target `ip:<addr>` name and the aggregate
`ipAggregateMonitorName` = `"ip-monitoring"`). Those ip debts are owned by
the `Monitor`'s `reconcileRGIPDebts`, which drives them to the desired set
on every poll and clears removed ones; a dropped RG is torn down wholesale
at RG removal. Because `reconcileMonitorDebtsLocked` builds `desired` from
`InterfaceMonitors` only, an ip key would always look "no longer desired",
so the removal loop SKIPS every ip key (`isIPMonitorName` — `ip:` prefix or
the aggregate constant). Without that skip, any unrelated config change
wiped a LIVE ip-monitoring debt from `monitorWeights`/`MonitorFails` and
recomputed the RG weight without it — and it did not self-heal (the
Monitor's `ipDebts` still recorded the debt installed, so the next
`reconcileRGIPDebts` poll saw `desired==installed` and no-op'd), so a node
with a dead monitored uplink jumped back to weight 255 and could win
election → blackhole. Fail-open (#5080 fold).

**Purge per-RG IP-monitor state on RG removal (#5990).** The manager clears
a removed RG's `monitorWeights` in `UpdateConfig`'s removal loop, but the
Monitor keeps its OWN per-RG maps: dampened `ipState` (keyed by
`(rgID, address)`), the installed-debt record `ipDebts` (keyed by rgID), and
the `ipThresholdState` mirror. `Monitor.UpdateGroups` now drops every entry
whose RG is no longer in config, alongside the `ifaceState` purge. Without
this, a same-id RG remove/re-add while a monitored target is DOWN left stale
`ipDebts[rg.ID]` behind: on re-add `reconcileRGIPDebts` saw
`desired==installed` by its OWN stale record and fired no `SetMonitorWeight`,
so the debt the manager already cleared was never re-installed — the re-added
RG carried a MISSING ip-monitor debt (weight stuck at 255) until the target
next transitioned (a dampened edge), and could stay primary with a dead
monitored uplink. Fail-open, narrow trigger. Purging `ipState` too means a
re-added RG whose target has since recovered starts from fresh dampening
rather than inheriting a stale down/hold-down state. A KEPT RG whose
ip-monitoring or targets merely changed is NOT purged here —
`reconcileRGIPDebts` owns that reconcile per-poll.

**Purge per-RG GARP count on RG removal (#6027).** `UpdateConfig` writes
`m.garpCounts[rg.ID]` ONLY when the config sets a positive
`gratuitous-arp-count`; the consumers (`pkg/vrrp`, `pkg/daemon`) treat an
absent entry as the default burst (3). The removal loop now
`delete(m.garpCounts, id)` alongside `monitorWeights` and `m.groups`, so a
same-id RG remove/re-add where the re-add omits an explicit count does not
inherit the prior incarnation's stale count — the entry stays absent and the
default applies. This is the third same-id-re-add map-lifecycle gap closed in
this loop, after the #5990 ip-monitor `ipState`/`ipDebts`/`ipThresholdState`
purge. The per-RG cleanup-on-removal maps are: `holdTimer` (stopped, #5245),
`monitorWeights` (interface + re-derivable ip debt), `garpCounts` (#6027), and
the group itself.

`LinkAttrsUp` is exported because the same carrier-aware read is needed
outside the monitor loop:

- `RethController.FormatStatus` (`reth.go`) and the reth-status displays
  for `show chassis cluster interfaces` — both the gRPC/remote-CLI path
  (`pkg/grpcapi`) and the local interactive CLI path (`pkg/cli`) — so a
  cable-pulled-but-admin-up RETH member shows `down`/`Down`, not
  `up`/`Up`, and the two display paths stay in agreement.
- The daemon no-reth-vrrp / private-rg-election VIP-readiness gate
  (`pkg/daemon.checkVIPReadinessForConfig`, #2090) — so a node is not
  judged ready to take over VIPs on an interface whose carrier is down
  (the #2070 hazard, surfacing on the VIP-takeover path).

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`, `pkg/vrrp`.

## Dependencies

`config`, `dataplane`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with default 30 ms VRRP advertisements (masterDownInterval ~97 ms).
- Planned shutdown: burst of 3× priority-0 advertisements; peer takes over
  in ~1 ms.
- Failback: ~130 ms (daemon startup + BPF load + sync hold release).
- Heartbeat: 200 ms interval, threshold 5 (1 s detection).
- Event debounce 500 ms before priority updates fire.

## Gotchas

- `Ready` and `TransferReady` are different gates. `Ready` allows VRRP to
  participate in election; `TransferReady` is the stricter gate for
  explicit operator-initiated `request chassis cluster failover`.
- `TakeoverHoldTime` adds extra delay before election when this node would
  immediately preempt. Used to avoid election thrash on simultaneous boot.
- **Removing an RG must stop its armed hold timer (#5245).** `SetRGReady`
  arms a per-RG `time.AfterFunc` takeover-hold timer whose closure captures
  the `*RedundancyGroupState` and re-runs election on expiry. `UpdateConfig`'s
  removal loop `Stop()`s and nils `rg.holdTimer` before `delete(m.groups, id)`
  — mirroring the `readiness.go` not-ready clear site and `Stop()`. Without
  this the closure keeps the removed group alive and still fires, running an
  election against removed state. Belt-and-suspenders: the closure also
  re-checks `m.groups[rgID] == rg` after taking `m.mu` (a timer that had
  already fired can race the teardown, since `AfterFunc.Stop()` does not
  cancel an in-flight callback) and no-ops if the group is gone or replaced.
- **`ManualFailover`/`ManualFailoverBatch` release `m.mu` for the pre-failover
  hook — a racing `ResetFailover` must not be clobbered (#5246).** Both take
  `m.mu`, mark `failoverInProgress`, then unlock to run the retryable pre-hook
  (which may sleep up to the retry timeout), re-lock, and write
  `State=SecondaryHold`. A `ResetFailover` in that unlocked window clears the
  failover and re-elects, but the trailing SecondaryHold write would silently
  overwrite it. Fix: a per-RG `failoverGen` counter — `ResetFailover` bumps it;
  the failover path snapshots it before unlocking and abandons its trailing
  write (single-RG returns nil; batch skips that member) if it changed. Keep
  `failoverInProgress` cleaned up on every exit path so a superseded failover
  cannot wedge the next one.
- **Owner-side transfer-out lease — a requester-side abort must not strand the
  demoted owner (#5079).** `RequestPeerFailover` drives the remote owner through
  `ManualFailover` (SecondaryHold, VRRP resigned) on the ACK, BEFORE the
  requester runs its own post-ACK readiness/commit checks. If a requester-side
  step fails after the ACK, `abortRequestedPeerFailover` rolls back only the
  requester's LOCAL override — it sends no abort frame to the owner, and the
  requester may roll back to a HEALTHY secondary. The pre-existing dual-resign
  guard in `electRG` never rescues this: it clears `ManualFailover` only when the
  PEER is itself resigned (weight 0) or in secondary-hold, not when the requester
  is a healthy secondary — so the owner would sit in secondary-hold forever and
  the cluster is left with NO primary (both secondary). Fix: the owner arms a
  **reqID-bound auto-restore lease** (`ArmRemoteTransferOutLease`) when a REMOTE
  request demotes it; the matching commit clears it (`ClearRemoteTransferOutLease`,
  reqID-bound so a stale commit cannot clear a newer request's lease). If the
  lease expires with no commit — abort, requester crash, or fabric loss — `electRG`
  restores the owner (clears `ManualFailover`, restores monitor-derived weight,
  re-elects). This is receiver-only self-healing: NO new wire frame (the reqID
  already rides the failover request/commit payloads), so no mixed-base
  compatibility concern, and it defends against requester death/partition that an
  abort frame could not. Only a REMOTE transfer-out arms a lease; `ManualFailover`
  / `ManualFailoverBatch` / `ForceSecondary` / `ResetFailover` clear any stale
  entry at their demotion/reset site so a deliberate operator or ISSU hold is
  never auto-restored (`ResetFailover` clears it for map hygiene — its restore is
  already gated on `ManualFailover`, which the reset clears; #6301). The lease
  duration (`SetRemoteTransferOutLeaseDuration`, default
  `DefaultRemoteTransferOutLease` = 30s, floored at 15s) is sized above the
  requester's worst-case post-ACK commit latency (local commit-ready settle +
  commit round-trip) so a legitimate slow commit never trips it. The upstream 20s
  failover-ACK cap (`failoverAckTimeout`, `sync.go`) further bounds this: if the
  owner's actuation barrier delays the applied-ack past 20s the requester times
  out and sends NO commit — the exact stranded case the lease-expiry restore
  handles — so a large `failoverActuateTimeout` cannot delay a real commit past
  the lease. reqID is threaded
  into `OnRemoteFailover`/`OnRemoteFailoverBatch`/`OnRemoteFailoverCommit`/
  `OnRemoteFailoverCommitBatch` (`sync.go`) to arm/clear it.
- **Every requester-side failure after `applyPeerTransferOutOverrideLocked`
  must roll the override back — including the commit's own election failure
  (#6527).** `commitRequestedPeerFailover` /
  `commitRequestedPeerFailoverBatch` arm the override BEFORE calling
  `runElection`, then return an error if the local RG did not reach primary.
  The batch caller already aborted on that error; the single-RG caller
  returned it bare and leaked the override. There is no expiry for
  `peerTransferOutOverride` — `applyTransferCommitOverridesOnPeerStateLocked`
  re-forces the peer to `SecondaryHold` on EVERY subsequent heartbeat with no
  time bound (unlike `peerTransferCommitGraceUntil`, which does expire) — so a
  leaked entry makes `electRG` take its "Peer transfer out" arm forever and
  self-promote this node as soon as whatever failed the election clears. Both
  nodes then hold the RETH VIP and virtual MAC, persistently. The failure is
  reachable without any fault injection: `RequestPeerFailover` releases `m.mu`
  around the fabric round-trip, `commitRequestedPeerFailover`'s re-check is
  `IsReadyForTakeover` (Ready/ReadySince only — it does NOT read weight), so an
  interface-monitor debt landing in that window passes readiness and then loses
  the election on the "Local weight 0" arm. The rollback is reqID-matched and a
  no-op on the two error returns that precede the override, so calling it on
  every commit error is safe. Invariant for future edits: the single-RG and
  batch request paths must agree on rollback at every failure point;
  `TestRequestPeerFailoverCommitFailureRollsBackOverrideOnBothPaths`
  (`failover_commit_rollback_6527_test.go`) binds the agreement rather than
  either copy.
- **The override must also not outlive the PEER INCARNATION that granted it
  (#6656).** #6527 above closed the requester-side commit-failure leak. It did
  not bound the override generally, and `handlePeerTimeout` — which already
  clears `ManualFailover` on every RG with the reasoning "the peer is dead, so
  the surviving node MUST be able to take over", plus `peerGroups`,
  `peerMonitors` and both peer version fields — left this one armed.

  That is the other half of the same transfer: `ManualFailover` parks the LOCAL
  node, `peerTransferOutOverride` forces our view of the PEER. Because it has no
  expiry and is re-applied to the rebuilt peer-group map on every heartbeat, an
  override that survives peer loss means the peer reconnects — a reboot, a
  rolling deploy, or simply a new process — and from its FIRST heartbeat this
  node overwrites its reported state with `SecondaryHold`, `electRG` takes the
  "Peer transfer out" arm, and this node self-elects primary regardless of what
  the peer says. `FormatStatus` renders the POST-override `m.peerGroups`, so the
  operator sees a healthy primary row whose session table is empty while the
  peer carries the traffic.

  `handlePeerTimeout` now clears it, after the two
  `suppressPeerTimeoutForTransferCommitLocked` consultations have declined so an
  in-flight commit keeps its suppression window. The time-bounded maps
  (`peerTransferCommitGraceUntil` / `localTransferOutHoldUntil`) are left alone:
  they expire on their own, and clearing them would shorten a window a live
  transfer may still be inside.

  Note for whoever investigates the next occurrence: `reassert_primary_node0`
  (`test/incus/cluster-setup.sh`) issues
  `request chassis cluster failover redundancy-group <rg> node 0` for EVERY RG
  on node0 after EVERY rolling deploy and swallows errors, so the arming step is
  routine rather than exceptional. And `RequestPeerFailover` early-returns
  "node is already primary" without touching the peer, which is why re-issuing
  the same failover to diagnose the state changes nothing.
- HA delete-sync callbacks fire from the GC loop. They must not block, and
  must log at `slog.Debug` — earlier `slog.Info` flooded at 15 req/s and
  drowned out real diagnostics (per CLAUDE.md logging rules).
- **`Manager.Start` must NOT hold `m.mu` across the monitor's `Stop()` (#4828).**
  The `Monitor` poll goroutine calls back into `SetMonitorWeight`, which takes
  `m.mu`; `Stop()` joins that goroutine via `wg.Wait()`. Holding `m.mu` while
  waiting for the goroutine to exit is an AB-BA deadlock (any config reload
  racing a monitor state-change permanently freezes the manager). `Start`
  therefore serializes on a dedicated `monStartMu`, takes `m.mu` ONLY to swap
  the `m.monitor` pointer, then runs the old `Stop()` / new `Start()` outside
  `m.mu`. This mirrors the `hbStartMu` discipline `StartHeartbeat` uses for the
  same reason (#4033). Any future method that both takes `m.mu` and joins a
  goroutine that re-enters the manager must follow the same split.
- The incremental sync sweep (`sync_conn_sweep.go`) re-syncs a session ONLY on
  `val.Created >= threshold` — it deliberately does NOT re-publish an
  established flow on `LastSeen` activity (#270 narrowed this; #131's
  `|| val.LastSeen >= threshold` clause was removed on purpose to keep the
  empty-sweep back-off and avoid >1/s control-socket contention). Standby
  retention of long-lived synced sessions is NOT the sweep's job — it is
  owned by the userspace Rust timer wheel's standby gate (#2120,
  `userspace-dp/src/session/expire.rs`): the standby HOLDS a peer-synced
  session for an RG it does not forward instead of aging it. Do NOT
  "restore the LastSeen re-sync" to fix a failover-retention bug — that
  re-introduces the per-second control-socket hammer #270 removed; the fix
  belongs in the wheel. The sweep narrowing is intentional and must stay.
- Session-sync key-only delete messages use `SessionStore.DeleteWithCompanions*`.
  Bulk stale reconciliation must use the known-value batch delete path through
  `SessionStore.ReconcileClusterBulk`, which deletes with the iterator's
  `(key,value)` snapshot. Reverse-session, DNAT/DNATv6, and persistent-NAT
  side effects are backend-owned; do not add local map cleanup in
  `pkg/cluster`.
- **Install-generation delete guard (#2170, #2221)**: every session install and
  every delete carries a per-`(sender,key)` monotonic install generation as a
  length-gated trailing `uint64` (see `docs/sync-protocol.md`). The sender
  (`sync_conn_gen.go`/`sync_bulk.go`) stamps installs from a single boot-seeded
  counter. A delete draws a **fresh, strictly-greater** generation
  (`takeDeleteGenV4/V6` → `nextInstallGen`) rather than echoing the install's
  stamp, so a delete always out-ranks the install it cancels — this is what makes
  a reordered delete/install pair orderable (#2221). The comparison is always
  same-`(sender,key)`-domain, even across an ownership change.
  The receiver keeps the authoritative per-key stored generation in
  `SessionSync.recvGenV4/V6` (the BPF C struct stays generation-free) and the
  apply layer refuses a delete whose generation is **strictly older** than the
  stored entry (`deleteClusterSynced*`, `DeletesStaleIgnored`) and refuses an
  install that would regress the stored generation (`installClusterSynced*`,
  `InstallsStaleIgnored`). Equality applies; `gen == 0` on either side falls
  back to today's unconditional behavior (rolling-upgrade safe). This stops a
  journaled/deferred delete for a closed flow from killing a same-5-tuple
  replacement that was re-synced with a newer generation. Do NOT reuse the
  synthesized `SessionID` for this — it is non-monotonic
  (`now_seconds<<16|slot`) and collides on same-second/same-slot reuse.
  **#2221 (same-generation reorder residual):** an applied non-zero delete now
  records the delete generation as a **TOMBSTONE** in `recvGenV4/V6` (it does not
  evict). A reordered install of the very session that delete cancelled carries
  the OLDER install generation and is refused by the install guard, so the
  standby converges to the master's state (session GONE) regardless of
  install/delete arrival order; a genuinely newer incarnation (re-stamped by a
  later sweep) carries a higher generation and still installs (last-writer-wins).
  A `gen == 0` (legacy) delete still evicts. The generation maps are bounded by
  `genGuardMapCap` (200000); on overflow the map is NEVER cleared (#2198 F1) — an
  existing key updates in place, a new key skip-records (degrades to safe gen-0)
  and bumps `GenMapOverflow`. The receiver also RESETS `recvGenV4/V6` when the
  peer begins a bulk transfer (`resetRecvGen` from the `syncMsgBulkStart`
  handler, #2198 F2) so a rebooted peer — whose monotonic-seeded counter
  legitimately restarts lower — has its cold-start bulk re-prime accepted instead
  of refused as stale (the stale-RETAIN inverse of #2170), and so a delete
  tombstone never permanently blocks a legitimate cold re-prime. The
  check→Put→record apply sequence is not held under one `recvGenMu` acquisition;
  it is safe because the per-peer receive path is single-threaded over the single
  active fabric (#2198 F3).
- **Config-epoch guard (#5274)**: distinct from the per-key install generation,
  every session install carries a `ConfigEpoch` — the #3931 config-sync
  generation (`configGenCounter`) the sender held when it queued the session
  (`stampInstallGen*`), as a length-gated trailing `uint64` on the session wire
  (`sync_protocol.go`). The receiver (`installClusterSynced*`) refuses an install
  whose epoch is **strictly older** than its `lastAppliedConfigGen`
  (`SessionsStaleConfigIgnored`), because the peer has since committed — and this
  node has applied — a newer config that may DENY the session. This closes the
  immediate-policy-invalidation gap: a session admitted under config A that lands
  after config B's `clearSessionsForDeletedPolicies` sweep is a stale permit the
  standby would otherwise forward under after failover. Both the stamp
  (`configGenCounter`) and the compare (`lastAppliedConfigGen`) are in the SAME
  sender→receiver #3931 namespace, so the comparison is meaningful across nodes.
  `epoch == 0` (legacy peer / local-origin) disables the check (rolling-upgrade
  safe); the reconnect `resetRecvGen` zeroes `lastAppliedConfigGen` so a
  rebooted-peer bulk re-prime is never falsely rejected. **That zeroing is
  serialized against every advance of the mark by `configGenMu` (#5084)** — the
  advance is a load/compare/store and the clear runs on a different goroutine
  (a receive loop, versus `configApplyLoop` for the applied mark and the *other*
  receive loop for the received mark), so a clear could land inside an advance
  and be lost, leaving a pre-reboot generation that refuses every generation the
  reconnected peer can produce. Writers of the three config-generation marks:

  | writer | mark(s) | goroutine | synchronisation |
  |---|---|---|---|
  | `recordAppliedConfigGen` | applied | `configApplyLoop` | `configGenMu` |
  | `recordRecvConfigGen` | received | receive loop (×2) | `configGenMu` |
  | `beginConfigApply` / `endConfigApply` | applying fence | `configApplyLoop` | `configGenMu` |
  | `resetRecvGen` | all three, clear to 0 | receive loop (×2) | `configGenMu` |
  | `initGenState` | all three | `NewSessionSync` | none — pre-`Start`, no goroutines yet |

  **What the #5084 incarnation fence actually covers, which is less than its
  name suggests.** `configItemIncarnationStale` drops a payload whose stamped
  incarnation differs from the current one, and the stamp comes from
  `connBootIncarnation(conn)` — *the connection the payload arrived on*. A
  connection that never received an incarnated `BulkStart` returns the ZERO
  value, and zero is the never-dropped class (plan §6 rule 4, fail open). In a
  two-fabric cluster only the fabric that primed carries a stamp; the other
  routinely carries config with none — measured directly: after a prime on
  fabric 0, `conn0` reports the incarnation and `conn1` reports `none`. So the
  fence covers *config arriving on a connection that itself primed under a
  now-replaced incarnation*, NOT "any config from a replaced boot". That is
  deliberate and it strands nothing, because rule 4 is symmetric — an
  un-incarnated payload passes at the receive site and at the apply site alike,
  so it can never raise the received mark and then be refused at apply. Read as
  the stronger claim it is not, this looks like a hole; it is a documented
  fail-open with matching behaviour on both sides of the queue.

  **The enqueue-side ordering cannot open the readiness gap (#6908, closed
  not-reproducible).** `recordRecvConfigGen` runs on a receive loop and can
  land *after* `resetRecvGen` has cleared the marks for a re-prime driven by
  the other fabric — a real ordering, not prevented by `configGenMu`, which
  serialises the writes but not their order. It was filed as leaving `received`
  high while `applied` lands low, wedging the #5563 manual-failover gate. It
  cannot: the reset that opens the window also removes the barrier that would
  hold the marks apart. `resetRecvGen` zeroes `lastAppliedConfigGen` in the same
  `configGenMu` transaction, and `shouldApplyConfigGen` is `last == 0 || gen >
  last`, so with `applied == 0` the late payload that raises `received` is the
  same payload that then applies and raises `applied`. Measured across the whole
  ordering space (late-raise alone; live re-push before and after it; live
  generation above and below the stale one) — `applied == received` in every
  case. A same-incarnation re-prime is a first-class case, not an edge
  (`notePeerBootIncarnation` rule 2, the #5450 forced resync), so the fence
  above is not what closes this; the reset's own transaction is. The gap between
  the marks CAN open, by the #6778 queue-full drop and by apply failure, both
  deliberate and separately tracked, plus a genuine one-apply transient while a
  queued newer generation is still in flight — which is the in-flight window
  #5563 exists to represent.

  Readers stay lock-free (the marks are atomics and `configEpochStale` runs per
  synced session install); a reader racing a writer observes one side of a
  single monotone step, which is the tolerance the marks already had. **The guard is
  Go-cluster-authoritative** — the userspace helper's `config_generation` is a
  *local* commit counter (`Manager.bumpGeneration`) that is not cross-node
  comparable, so the receiver rejects the stale install BEFORE forwarding it to
  the helper, and no config-epoch field or guard is added on the Rust side.
  **Apply-in-progress fence (#6284, item 2):** the bare `epoch <
  lastAppliedConfigGen` compare closes the gap only once the high-water has
  advanced, but the high-water advances AFTER `OnConfigReceived` returns while
  the `clearSessionsForDeletedPolicies` sweep runs INSIDE it — leaving a sub-µs
  window where a racing install is admitted against the stale high-water.
  `configApplyLoop` raises `applyingConfigGen` to the generation it is applying
  BEFORE the apply and lowers it only AFTER the high-water advances (success) or
  the apply fails; `configEpochStale` refuses against `max(applyingConfigGen,
  lastAppliedConfigGen)` (fence read first), so an older-epoch install racing the
  window is refused against the applying generation instead of admitted. The
  guard still covers only the config-authority → peer direction; the reverse
  active/active direction stays a documented fail-OPEN residual on #6284 (item 1,
  needs a bidirectional config-gen namespace #5274 scoped out).
- **RT_FLOW session id (#5212)**: distinct from the per-key install generation,
  every session install carries the ORIGINATING node's stable RT_FLOW session id
  (`SessionValue{,V6}.RTFlowSessionID`, the dataplane's
  `SessionTable::alloc_session_id` value) as a length-gated trailing `uint64` on
  the session wire (`sync_protocol.go`, appended after the #5274 `ConfigEpoch`).
  Unlike the guards above this is pure identity carriage — the receiver never
  rejects on it. The peer helper's `upsert_synced_with_origin` ADOPTS the id on
  import (via `SessionSyncRequest.session_id` → `build_synced_session_entry`)
  instead of minting a fresh node-local one, so a session's RT_FLOW
  SESSION_CREATE (origin node) and SESSION_CLOSE (peer, after failover) share one
  correlatable id across HA nodes. `id == 0` (legacy peer / synthesized delta)
  falls back to a fresh local id (rolling-upgrade safe). Full path:
  `docs/sync-protocol.md` "RT_FLOW Session Id (#5212)".
- Dual-active overlap is intentional: primary sets `rg_active=true`
  immediately on becoming master; secondary defers `rg_active=false` until
  it sees the VRRP BACKUP event. Brief overlap, never both inactive.
- `handlePeerTimeout` runs its peer-timeout guard (`peerTimeoutGuardFn`) with
  `m.mu` released, so the receiver read path can run `handlePeerHeartbeat`
  during the call for ANY guard duration (a configured slow guard only widens
  the window). After the guard it re-checks heartbeat STALENESS via
  `peerHeartbeatFreshLocked`, not just `peerAlive` (#2080): a heartbeat that
  lands during the guard window keeps `peerAlive` true but is a fresh
  heartbeat, so the only correct post-guard question is "is the heartbeat
  fresh again?". `peerHeartbeatFreshLocked`
  re-reads the receiver's `lastSeen` against the live monotonic clock (test
  seam: `peerHeartbeatFreshFn`); a fresh heartbeat aborts the peer-lost
  transition and prevents spurious failover churn. A nil receiver / unset seam
  reports not-fresh, so the no-receiver call paths behave exactly as before the
  re-check existed.

  **#6198/#6666 correction:** the BPF-ABI `SessionID` was described here as
  `now<<16|slot` — a composition #6198 removed (it collapsed every session
  converted in the same second onto one id). Since #6666 the mirror ADOPTS this
  RT_FLOW id when the peer sent one, so the two are no longer distinct for a
  peer-synced session; a node-local id is minted only for a legacy peer that
  sent none. That is what makes `show security flow session` and RT_FLOW render
  one id for one session.

- **The peer heartbeat-ack capability is peer-INCARNATION scoped, not
  process-sticky (#5718 C01a).** `SessionSync.peerHeartbeatAckEver` latches
  when the connected peer replies `syncMsgHeartbeatAck`, and that latch is what
  switches two paths from "assume healthy" to "enforce": the `receiveLoop`
  missed-heartbeat teardown (`sync_conn_read.go` — two read deadlines with no
  traffic closes the connection) and `PeerHealthy()`'s silence window
  (`sync.go`), which `computeUserspaceTransferReadiness` consults before
  allowing a manual failover. The capability describes the PEER PROCESS, so
  `handleDisconnect` clears it on FULL disconnect, right beside `clockSynced` —
  same reason, same place. It must NOT be cleared on a partial disconnect (one
  fabric link down, the other still up): that is the same peer process, and
  clearing there would disarm both enforcement paths on every link blip.
  Leaving it latched across a peer DOWNGRADE is the defect this replaced — new
  build acks, peer rolls back to a build that never acks, and the stale latch
  turns a healthy old peer into permanent connection churn plus a
  failover-readiness block ("session sync disconnected"). Both directions are
  pinned by `heartbeat_ack_incarnation_5718_test.go`.

  **The incarnation ends at TWO edges, not one (#5718 fold F1).**
  `handleDisconnect`'s full-disconnect block cannot see a SUPERSESSION, and
  supersession is precisely the peer-reboot shape: a peer that dies hard sends
  no FIN/RST, so our TCP connection stays ESTABLISHED, `fabricConnectLoop` will
  not redial a slot it believes is connected, and the peer's NEW process dials
  in and lands in `installConn`. `installConn` closes the old connection and
  takes the slot; the old `receiveLoop` then calls `handleDisconnect`, finds
  the slot already holding the new conn, and returns down the "ignoring stale
  disconnect" default branch without clearing anything. `installConn` therefore
  clears the latch when it REPLACES a live connection in a fabric slot, as well
  as on the full-disconnect edge. It deliberately does not clear when a link
  comes up into an EMPTY slot beside a surviving one — that is the same peer
  process, the mirror of the partial-disconnect scope control above.

  **Only a currently-installed connection may latch it (#5718 fold F1).**
  `handleMessage` routes `syncMsgHeartbeatAck` through `noteHeartbeatAck`,
  which stores under `s.mu` — atomic with `installConn`'s clear. Without that
  ordering an ack already read off the superseded connection re-arms the latch
  for the incoming incarnation right after the clear, restoring the exact state
  the clear removed. It also means the pre-install handshake-pending frame
  cannot arm an enforcement path: an ack is never a legitimate FIRST frame,
  because we only send `syncMsgHeartbeat` after a read deadline elapses on an
  established connection.

  **Slot membership is NOT sufficient — the slot carries an incarnation stamp
  (#5718 fold F1b).** With TWO fabric slots, `s.conn0 == conn || s.conn1 ==
  conn` asks only whether a connection sits in *either* slot, and after a peer
  reboot the dead incarnation still occupies one of them: no FIN/RST means both
  of its sockets stay ESTABLISHED while the new process supersedes just the
  slot it dialled. An in-flight ack off that survivor passes a membership test
  and re-arms the capability the supersession cleared — the previous
  incarnation enforced against the current one, the same defect one level up.
  `SessionSync` therefore carries `peerIncarnation` plus per-slot `conn0Gen` /
  `conn1Gen` (all under `mu`): `installConn` stamps each slot at install, and
  `connIsCurrentIncarnationLocked` accepts an ack only when the slot's stamp
  equals `peerIncarnation`.

  The counter advances when a supersession replaces a connection that belonged
  to the CURRENT incarnation. A supersession that merely evicts an
  ALREADY-STALE connection is the new incarnation reclaiming its second slot,
  not a further change: advancing there would strand the connection that
  legitimately proved the capability at a stale stamp, permanently disarming
  both enforcement paths for the life of that connection. Both directions, and
  both fabric orderings, are pinned in
  `heartbeat_ack_incarnation_5718_test.go` — the classification and the
  acceptance test each branch per fabric, so a single-fabric fixture would
  leave one arm of each switch unbound.

  Residual, deliberately open. This was previously described as a THIRD
  incarnation dialling into the slot that still held a stale connection. Fold
  r4b's eviction made that shape unreachable: no RETIRED-STAMPED connection
  remains installed after a recognized supersession for a later incarnation to
  land on. (Precisely that — the accepted residual below can still leave a
  semantically dead connection installed under a falsely-CURRENT stamp, and a
  third incarnation can physically land on that corpse; it is then classified as
  replacing a current connection, which advances the incarnation and evicts, so
  it does not reach the old no-advance outcome.)

  The residual that survives it is the empty-alternate-slot reboot — a peer
  whose replacement enters through a slot that is already empty is never
  classified as a supersession at all, so the incarnation never advances and
  none of this machinery runs. It is described in full below and in
  `evictStaleIncarnationConnsLocked`'s KNOWN-INCOMPLETE note. Both shapes need
  the same thing: a peer-supplied boot incarnation on the wire, which #5480
  tracks and #6669 implements. Closing it is a wire change, not a local one.

  `installConn` does NOT clear on the full-disconnect edge, because whenever the
  registry is empty the capability is already clear — reached either by
  initialization (a fresh `SessionSync` is empty having never seen a disconnect)
  or because `handleDisconnect` owns the nonempty-to-empty transition. Note the
  reason is NOT that `conn0`/`conn1` are nilled nowhere else — since fold r4b
  `evictStaleIncarnationConnsLocked` nils them too. It is that eviction cannot
  leave the registry EMPTY (below), so an empty one still implicates
  `handleDisconnect` alone. Adding the condition back is inert
  rather than wrong, so no behavioural test can reject it; what the tests pin
  instead is the PREMISE. That has two halves, because the behavioural half
  alone would be decorative (removing `handleDisconnect`'s clear already reds
  an older assertion): `TestPeerHeartbeatAckClearedWheneverRegistryEmpties`
  drives every emptying path it knows of, and
  `TestOnlyHandleDisconnectEmptiesTheRegistry` asserts on the package AST which
  functions may assign `conn0`/`conn1` nil. A future teardown that empties a
  slot elsewhere reds the structural guard even though every behavioural test
  would still pass, and at that point this narrowing must be revisited.

  `evictStaleIncarnationConnsLocked` is the one exemption in that allowlist. It
  nils a slot, but it provably cannot EMPTY the registry, and since fold r6 for
  reasons intrinsic to the function rather than to its caller: it skips the keep
  slot, **and** it refuses to evict anything at all unless that slot is
  occupied. The second half matters because the allowlist exempts by function
  NAME. Before it, soundness rested on what the single caller happened to do —
  `installConn` installs before it evicts — so a future second call site would
  have inherited the exemption without inheriting the property it was granted
  for, and could have emptied the registry with every guard green:
  `TestInstallConnNeverLeavesTheRegistryEmpty_5718` drives the existing call
  site and cannot see a new one.

  Both are pinned. `TestEvictionRefusesToEmptyTheRegistry_5718` calls the helper
  directly with an unoccupied keep slot (and with an out-of-range index) and
  asserts it declines; `TestInstallConnNeverLeavesTheRegistryEmpty_5718` still
  covers the live path, so losing the `keepIdx` skip reds there. Removing the
  refusal reds only the former — which is the point: the pre-r6 tests all stay
  green under that mutation, so they were not covering it.

  **The SEND path is incarnation-aware too (#5718 fold r4).** The stamp
  originally taught only the ACK path that an installed connection can belong
  to a dead peer. `activeConnLocked` still picked by raw slot occupancy, so
  after a peer reboot whose replacement dials FABRIC 1, `conn0` — the dead
  incarnation's still-ESTABLISHED socket — was handed to every sender reached
  through `getActiveConn`: bulk sync (which pins it once and streams the whole
  session table), config sync, failover requests and acks, the session writer.
  `preferredFabricLocked` now prefers a CURRENT-incarnation connection and only
  then applies the historical fab0-before-fab1 order. When nothing is current
  it falls back to the old preference rather than returning nil, so the
  pre-existing self-correcting path (write fails -> `handleDisconnect`) is
  unchanged.

  `installConn` computes `activeAfter` from the same helper, AFTER the
  incarnation advance and the slot stamp — otherwise the cold-prime decision
  disagrees with where the data will actually be sent.

  **Selection was not enough — the retired connection is EVICTED (#5718 fold
  r4b).** `preferredFabricLocked` fixed where traffic GOES. It did not change
  what is INSTALLED, and three other paths read raw slot occupancy, so the dead
  incarnation's socket (ESTABLISHED forever — a hard reboot sends no FIN/RST)
  kept speaking for a process that no longer exists:

  - `handleDisconnect` computes `connected := s.conn0 != nil || s.conn1 != nil`.
    When the one LIVE connection later dropped it took the "still connected"
    branch: `stats.Connected` stayed true — so `PeerHealthy()` reported a
    healthy peer with ZERO live connections, the incarnation advance having
    already cleared the capability latch that gates its silence check — barrier
    and failover waiters were never released with `failoverAckDisconnected` and
    blocked until their own timeouts, `OnPeerDisconnected` never fired, and the
    in-progress bulk receive was never reset.
  - `fabricConnectLoop` skips a fabric whose slot is non-nil, so the link to the
    new peer process was never redialled there and the cluster silently ran on
    one fabric.
  - `installConn`'s `d.wasDisconnected` needs BOTH slots nil, so the
    full-disconnect cold-prime edge was unreachable while the corpse sat in a
    slot.

  Nothing else removed it either: `receiveLoop`'s missed-heartbeat teardown is
  gated on `peerHeartbeatAckEver`, which the incarnation advance clears —
  identifying the connection as retired is precisely what disarmed its only
  eviction path. `installConn` therefore calls
  `evictStaleIncarnationConnsLocked`, closing and clearing every slot other than
  the one just filled whose stamp is no longer current, restoring in one place
  the invariant all three readers already assume: *installed* means *belongs to
  the peer incarnation in force*.

  Consequence for the two generation checks: a slot can no longer hold a
  stale-stamped connection, so `preferredFabricLocked`'s and
  `connIsCurrentIncarnationLocked`'s comparisons are fail-closed BELTS for an
  install path added later that forgets to evict, not the load-bearing gates.
  Their tests build that state by hand and say so, rather than pretending to
  drive it. Note neither belt could substitute for the eviction: both govern one
  reader each, and the three readers above never come through either.

  Cost of a false positive: a supersession that is really the same peer process
  re-dialling a half-open socket also drops the other fabric, which
  `fabricConnectLoop` redials within a second, plus one redundant authoritative
  bulk. That is the trade #5480 already took, and it CONVERGES — the
  pre-eviction shape did not, because the retired socket stayed installed and
  un-evictable until TCP gave up retransmitting, which is minutes.

  **ACCEPTED RESIDUAL: a rebooted peer entering through an EMPTY alternate slot
  (#6910, blocked on #6669).** Everything above keys off `installConn`'s
  occupancy-based classification, and there is one reboot shape that
  classification cannot see:

  1. Peer A holds `conn0`; `conn1` is already down/empty.
  2. A hard-reboots. `conn0` stays ESTABLISHED locally — no FIN/RST.
  3. A's replacement A' connects first (or only) on fabric 1.
  4. `installConn` sees a NON-empty registry but an EMPTY target slot, so
     `wasDisconnected` is false and `supersededCurrent` is false. No incarnation
     advance, no eviction, no capability clear, no cold-prime arm.
  5. A' is stamped with the SAME incarnation as the dead `conn0`, so both look
     current and `preferredFabricLocked` picks dead fabric 0 over live fabric 1.
  6. When `conn0` eventually drops, `conn1` keeps `connected` true, so the
     full-disconnect path never runs and A' never receives the survivor's
     session table. The next failover to it can blackhole.

  **Why this is not fixed locally.** Step 4 is observationally IDENTICAL to the
  routine case — the same peer process bringing up its second fabric after a
  link flap. Both present as "an empty slot filled while another slot is
  occupied", and nothing on the wire distinguishes them: the sync handshake
  carries no peer-cold / boot-incarnation / table-count signal (the same gap
  #5480 records and defers). Any local heuristic that treats step 4 as a reboot
  necessarily also treats every routine second-fabric recovery as one, which
  re-primes the entire session table on every link blip and destroys the #466
  flap suppression #5480 deliberately preserved.
  `TestSecondFabricComingUpIsNotEvicted_5718` and
  `TestRoutineInstallDoesNotReArmColdPrime_5718` pin the ROUTINE reading on
  purpose. They are correct as written; do NOT "fix" them into failing to close
  this residual. The separating signal is a peer-supplied boot epoch, which
  #6669 introduces (signed in the heartbeat) and #6910 consumes.

  **What is and is not bounded, since the two halves differ.** Steps 5 and 6 do
  not decay at the same rate:

  - Step 5 (dead `conn0` preferred) is TIME-BOUNDED for an ack-capable peer, and
    for a reason specific to this path: no incarnation advance happens here, so
    `peerHeartbeatAckEver` is NOT cleared and `receiveLoop`'s missed-heartbeat
    teardown stays ARMED. `conn0` is closed after 2 read deadlines (~20s at the
    10s default). This is the opposite of the two-fabric supersession case
    above, where the advance clears the latch and disarms that teardown — which
    is exactly why THAT case needed eviction and this one partially self-heals.
    For a peer that never proved ack support the latch is false, enforcement is
    intentionally disabled, and no bound applies.
  - Step 6 (A' never primed) is NOT bounded and does not self-heal. When
    `conn0` finally drops, `handleDisconnect` takes the `else if
    !s.outboundBulkAcked` branch — so A' is re-primed ONLY if our outbound bulk
    to the OLD A had never been acked. In steady state it had been, so no
    re-drive fires and A' keeps an empty session table indefinitely. This is the
    half that genuinely requires #6669's boot epoch, and it is the half #6910
    must close.

  **A supersession re-arms the cold prime (#5718 fold r4).** `needColdPrime`
  was armed only on the full-disconnect edge. Superseding a CURRENT connection
  is positive evidence of a new peer process — the signal #5480 records as
  unavailable on the wire, which is why that path re-primes unconditionally. A
  rebooted peer has an EMPTY session table, so leaving the obligation unarmed
  leaves the standby with no synced sessions and blackholes every established
  flow on the next failover to it. Re-priming is idempotent, so the cost of
  being wrong is one redundant bulk. A link filling an EMPTY slot beside a live
  one does NOT re-arm: same peer, and re-priming there would re-bulk on every
  routine fabric flap (#466).

  **Atomicity of the ack is bound, not merely asserted (#5718 fold r3).** Every
  scenario test calls `installConn` and `handleMessage` in sequence, so none of
  them opens the window `s.mu` exists to close — an implementation that checks
  under the lock, releases it, and only then stores would pass all of them
  while letting a supersession land in between and resurrect a just-cleared
  capability. `noteHeartbeatAckMidpointHook` (nil in production) widens that
  window so a test can start a competing `installConn` from inside it: under
  the real implementation the competitor BLOCKS on `s.mu` until the ack
  returns, so it cannot interleave. The assertion is on final state, so it is
  deterministic in both shapes, and only the correct implementation depends on
  the (generous) wait EXPIRING.
