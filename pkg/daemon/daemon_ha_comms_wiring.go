package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Cluster-comms construction helpers extracted from Daemon.startClusterComms
// (#6428). Every body below is byte-identical (modulo one level of
// de-indentation) to the block it replaced; the call sites in
// daemon_ha_sync.go appear in the identical order, so the startup sequence and
// every goroutine spawn point are unchanged.

// resolveClusterVRFDevice determines which VRF device the cluster control /
// fabric sockets must bind to. Extracted verbatim from startClusterComms
// (#6428) — pure code motion, no behaviour change.
//
// Order contract: the caller must invoke this BEFORE spawning the heartbeat
// goroutine and the session-sync constructor goroutine; both take the result
// by value.
func (d *Daemon) resolveClusterVRFDevice(cc *config.ClusterConfig) string {
	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	// Check mgmtVRFInterfaces first, then fall back to probing the control
	// interface directly (handles config-only mode where applyConfig may
	// have run but mgmtVRFInterfaces is empty due to VRF creation failure).
	vrfDevice := ""
	if len(d.mgmtVRFIfaceSet()) > 0 {
		vrfDevice = config.ManagementVRFDeviceName
	} else if cc.ControlInterface != "" {
		// Control/fabric interfaces (em*, fab*) are always placed in
		// vrf-mgmt by the compiler. Check if the VRF device exists.
		if _, err := net.InterfaceByName(config.ManagementVRFDeviceName); err == nil {
			vrfDevice = config.ManagementVRFDeviceName
		}
	}
	return vrfDevice
}

// startHAWatchdogHeartbeat starts the BPF watchdog heartbeat goroutine for the
// cluster comms epoch owned by commsCtx. Extracted verbatim from
// startClusterComms (#6428) — pure code motion, no behaviour change.
//
// Order contract: called after beginClusterCommsEpoch (the goroutine captures
// commsCtx) and at the same point in the constructor sequence as before, so the
// first tick lands at the same offset relative to heartbeat/session-sync start.
// The dataplane gate is still evaluated ONCE here and re-read per tick (#3917).
func (d *Daemon) startHAWatchdogHeartbeat(commsCtx context.Context, cc *config.ClusterConfig) {
	// Start BPF watchdog heartbeat: write monotonic timestamp to ha_watchdog
	// map every 500ms for each configured RG. If the daemon is SIGKILL'd,
	// the timestamp goes stale and BPF stops forwarding within 2s.
	//
	// #3917: gate on the published dataplane only (not the startup RG
	// count) and re-read the
	// CURRENT redundancy-group set each tick. Comms are only restarted on a
	// transport-field change, so binding cc.RedundancyGroups here would
	// starve a day-2 RG (added by a later commit) of watchdog heartbeats ->
	// its watchdog goes stale -> the dataplane stops forwarding for it.
	// This mirrors the live-config read the fence path now uses.
	if d.dataplane() != nil {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-commsCtx.Done():
					return
				case <-ticker.C:
					// #2114: ONE load per tick, shared across the RG loop
					// (plan §5.3 rule 1) — never per-RG, never a lifetime
					// capture.
					rt := d.dataplane()
					if rt == nil {
						continue
					}
					rgs := d.currentRedundancyGroups()
					if len(rgs) == 0 {
						continue
					}
					var ts unix.Timespec
					_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
					now := uint64(ts.Sec)
					for _, rg := range rgs {
						if err := rt.HA().SetHAWatchdog(commsCtx, rg.ID, now); err != nil {
							slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
						}
					}
				}
			}
		}()
		slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
	}
}

// clusterSyncTransport picks the session/config-sync transport: the dedicated
// control link when it is fully configured, else the fabric (legacy).
// Extracted verbatim from startClusterComms (#6428) — pure code motion.
// Returns (interface, peer address, transport label).
func clusterSyncTransport(cc *config.ClusterConfig) (string, string, string) {
	// Start session/config sync on the control link (same interface as
	// heartbeat, port 4785). Consolidates all control-plane traffic onto
	// the dedicated control path. Falls back to fabric if no control
	// interface is configured (legacy compatibility).
	syncIface := cc.ControlInterface
	syncPeerAddr := cc.PeerAddress
	syncTransport := "control-link"
	if syncIface == "" || syncPeerAddr == "" {
		syncIface = cc.FabricInterface
		syncPeerAddr = cc.FabricPeerAddress
		syncTransport = "fabric"
	}
	return syncIface, syncPeerAddr, syncTransport
}

// wireSessionSyncTransportRefs installs the auth provider on the freshly
// published session-sync object and records the transport label plus the peer
// addresses used for gRPC peer dialing. Extracted verbatim from
// startClusterComms (#6428) — pure code motion.
//
// Order contract: MUST run after publishSessionSyncIfCurrent succeeded and
// BEFORE ss.Start opens listeners/dialers — the auth provider has to be in
// place before the first connection is accepted.
func (d *Daemon) wireSessionSyncTransportRefs(ss *cluster.SessionSync, cc *config.ClusterConfig, syncTransport, syncPeerAddr, syncLocal1 string) {
	// #4107 F23: authenticate the session-sync stream with the same
	// control-link PSK the heartbeat + fabric-gRPC use (#4357). The
	// cluster Manager supplies both the key and the heartbeat
	// downgrade-guard signal (HeartbeatPeerAuthSeen). With no key
	// configured the stream stays legacy unauthenticated (dual-accept).
	ss.SetAuthProvider(d.cluster)

	d.cluster.SetSyncTransport(syncTransport)

	// Store sync peer addresses for gRPC peer dialing (session queries etc).
	d.syncPeerAddr = syncPeerAddr
	if syncLocal1 != "" {
		d.syncPeerAddr1 = cc.Fabric1PeerAddress
	}
}

// startFabricGRPCListeners spawns the poller that starts the gRPC fabric
// listener(s) once d.grpcSrv exists (it is set after startClusterComms
// returns). Extracted verbatim from startClusterComms (#6428) — pure code
// motion; the goroutine is spawned at the same point in the sequence.
func (d *Daemon) startFabricGRPCListeners(commsCtx context.Context, syncIP, syncLocal1, vrfDevice string) {
	// Start gRPC fabric listener(s) so peer can proxy monitor requests.
	// d.grpcSrv is set after startClusterComms returns, so we poll briefly.
	// Uses the sync interface address (fabric or control-link).
	// When dual-fabric is configured, listen on both fabric IPs.
	go func() {
		for i := 0; i < 30; i++ {
			if d.grpcSrv != nil {
				// #8597 (muse-004 K29 siblings): these are LISTEN addresses, and
				// an IPv6 fabric literal formatted as "%s:50051" yields
				// `2001:db8::2:50051` — which is not an address, so the fabric
				// gRPC listener never binds and the peer-proxy path is dark on
				// an IPv6-only fabric. Same class as the dial site in
				// `grpcapi/server_diag.go` and as #4909's `pkg/cli/peer.go`.
				grpcAddr := net.JoinHostPort(syncIP, "50051")
				if syncLocal1 != "" {
					// Extract fab1 local IP (syncLocal1 is "ip:4785").
					fab1Host, _, _ := net.SplitHostPort(syncLocal1)
					grpcAddr1 := net.JoinHostPort(fab1Host, "50051")
					go d.grpcSrv.RunFabricListener(commsCtx, grpcAddr1, vrfDevice)
					slog.Info("gRPC dual fabric listeners", "fab0", grpcAddr, "fab1", grpcAddr1)
				}
				d.grpcSrv.RunFabricListener(commsCtx, grpcAddr, vrfDevice)
				return
			}
			time.Sleep(time.Second)
		}
	}()
}

// wireSessionSyncConfigCallbacks wires the config-sync receive and
// config-apply-health callbacks. Extracted verbatim from startClusterComms
// (#6428) — pure code motion.
//
// Order contract: every ss.On* callback MUST be installed before ss.Start,
// which spawns the accept/connect goroutines that invoke them.
func (d *Daemon) wireSessionSyncConfigCallbacks(ss *cluster.SessionSync) {
	// #8121: the standby installs the peer's IDLE persistent-NAT leases —
	// the population session sync cannot carry, because a lease with no
	// flows has no session to be derived from.
	d.wirePersistentNatLeaseCallbacks(ss)

	// Wire config sync callback: when secondary receives config from primary.
	ss.OnConfigReceived = func(configText string) error {
		d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
		return d.handleConfigSync(configText)
	}

	// #6387: surface a persistent config-sync APPLY failure as a
	// node-global CF monitor-failure / degraded health. configApplyLoop
	// fires this on the time-based stale-duration edge (raise) and on
	// the first post-failure success (clear); the cluster manager stores
	// it as a diagnostic-only annotation. This never gates failover —
	// manual failover stays gated solely by ConfigStale(); crash
	// takeover stays ungated.
	ss.OnConfigApplyHealth = func(failing bool, reason string) {
		d.cluster.SetConfigSyncHealth(failing, reason)
	}

	// #7328: the peer refused or failed to apply the generation we pushed.
	// Re-arm the #5863 push marker so the next reconcile tick re-sends it —
	// without this the marker suppresses every further push of that generation
	// on the live connection and the standby stays stranded until a new commit
	// or a reconnect, defeating the re-push eligibility M-2/#4151 preserves.
	ss.OnPeerConfigApplyFailed = func(gen uint64) {
		slog.Warn("cluster: peer did not apply our config generation — re-arming the config-sync push marker",
			"gen", gen)
		d.invalidateConfigSyncPushed()
	}
}

// wireSessionSyncPeerCallbacks wires the peer-lifecycle callbacks: connect,
// bulk-sync received/acked, forward-session installed, and disconnect.
// Extracted verbatim from startClusterComms (#6428) — pure code motion.
//
// Order contract: installed before ss.Start, whose first connection runs the
// authoritative cold-prime bulk inside handleNewConnection.
func (d *Daemon) wireSessionSyncPeerCallbacks(ss *cluster.SessionSync) {
	// Wire peer connected callback: reconcile config to the returning
	// peer. #5863: the push is level-triggered, not a one-shot connect
	// edge — reconcileConfigSyncToPeer re-evaluates the RG0-authority +
	// stability + config-generation invariant and pushes at most once
	// per connection/generation. A node that is secondary or too young
	// at connect time correctly skips here, and a LATER promotion or
	// stability crossing re-pushes via the promotion hook / reconcile
	// loop, instead of leaving the peer indefinitely divergent.
	ss.OnPeerConnected = func() {
		d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
		d.onSessionSyncPeerConnected()
		// #2239 Q7: a peer that just (re)connected (e.g. a restarted
		// standby) has an empty in-memory peerDHCPLeases set. Nudge a
		// full lease re-push so it is not briefly empty until the next
		// heartbeat tick. The nudge is RG-MASTER gated inside the push
		// loop (this node pushes only its own owned set), so it is safe
		// regardless of RG0 config authority — done before the
		// RG0-only config-push gating below.
		if cc := d.clusterConfig(); cc != nil && cc.DHCPLeaseSync {
			d.nudgeDHCPLeaseSync()
		}
		// #4385: a peer that just (re)connected may have missed the
		// one-shot empty IPsec SA advertisement during the gap, or (a
		// same-process standby) retained a stale peer set across the
		// blip. Nudge a forced re-advertise of the current set (empty or
		// not) so it converges — gated on primary + IPsecSASync inside
		// advertiseIPsecSAOnce, so it is safe regardless of this branch.
		if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync {
			d.nudgeIPsecSASync()
		}
		d.reconcileConfigSyncToPeer("peer-connect")
	}

	ss.OnBulkSyncReceived = func() {
		d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
		slog.Info("cluster: session sync complete, releasing VRRP hold")
		d.onSessionSyncBulkReceived()
	}

	ss.OnBulkSyncAckReceived = func() {
		d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync acknowledged by peer")
		d.onSessionSyncBulkAckReceived()
	}

	ss.OnForwardSessionInstalled = func() {
		d.scheduleStandbyNeighborRefresh()
	}

	// #5085: do NOT wire the event-stream export as the cold-prime
	// bulk override. That path delivered sessions as async, LOSSY
	// event-stream incrementals (QueueSessionV4/V6 -> non-blocking
	// sendCh) and then sent an EMPTY BulkStart/BulkEnd, so the receiver
	// recorded zero session keys and skipped authoritative stale
	// reconciliation — a stale peer-owned session the standby held
	// survived cold-prime. Cold-prime now uses the lossless BulkSync
	// direct-write window (doBulkSync), which delimits a COMPLETE
	// authoritative snapshot the receiver reconciles against.
	//
	// #6031: that window is now framed from TABLE TRUTH, not from the
	// BPF `sessions`/`sessions_v6` conntrack maps BulkSync walks. Under
	// the userspace dataplane those maps are a best-effort DISPLAY
	// mirror — the helper's transit forward install never publishes a
	// conntrack row — so the walk cannot see the transit sessions that
	// dominate a forwarding node. Combined with #5085's authoritative
	// reconcile (absent from the window => DELETED), framing cold prime
	// from the mirror DELETED the standby's live peer-owned transit
	// sessions. BulkSnapshotSource supplies the owner-RG-filtered live
	// set from the helper's SessionTable via ExportOwnerRGSessions
	// instead, and doBulkSync fails CLOSED if it errors rather than
	// falling back to the destructive mirror walk.
	ss.BulkSnapshotSource = d.userspaceBulkSnapshot

	ss.OnPeerDisconnected = func() {
		d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer disconnected (all fabrics)")
		d.onSessionSyncPeerDisconnected()
	}
}

// wireSessionSyncFailoverCallbacks wires the peer-driven remote-failover
// request/commit handlers (single and batch) and the actuation barriers the
// applied-ack waits on. Extracted verbatim from startClusterComms (#6428) —
// pure code motion.
//
// Order contract: installed before ss.Start; a peer failover request that
// arrived on an unwired object would be silently rejected.
func (d *Daemon) wireSessionSyncFailoverCallbacks(ss *cluster.SessionSync) {
	// Wire remote failover: when the peer requests us to transfer an RG
	// out of primary and explicitly acknowledge the result.
	// Guard: only honor the request if we are actually primary for
	// this RG. Stale/delayed sync messages can arrive after we've
	// already transitioned to secondary — blindly calling
	// ManualFailover would cause dual-resign (both nodes secondary)
	// and a 30-second traffic blackhole.
	ss.OnRemoteFailover = func(rgID int, reqID uint64) error {
		if !d.cluster.IsLocalPrimary(rgID) {
			return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
		}
		slog.Info("cluster: remote failover request from peer", "rg", rgID, "req_id", reqID)
		// #5640: arm the fence-completion barrier BEFORE ManualFailover
		// enqueues the async demotion event, so watchClusterEvents
		// cannot actuate-and-forget before WaitFailoverApplied observes
		// it. The applied-ack (sync layer) then waits on this barrier.
		barrier := d.armFailoverActuation(rgID, reqID)
		outcome, err := d.cluster.ManualFailover(rgID)
		if err != nil {
			d.disarmFailoverActuation(rgID, reqID, barrier)
			slog.Warn("cluster: remote failover failed", "rg", rgID, "err", err)
			return err
		}
		// #8000: a supersede enqueues NO demotion event, so nothing will ever
		// actuate this barrier. Left armed, the applied-ack below waits the full
		// fence timeout and then reports "timed out waiting for local fence
		// actuation of redundancy group N" — a real error, naming the right RG,
		// and blaming the wrong subsystem: the fencing path is fine, a
		// concurrent reset simply won. Dropping the barrier makes
		// WaitFailoverApplied return immediately (it returns nil when none is
		// armed), so the correct outcome stops being reported as an
		// infrastructure fault.
		if outcome == cluster.FailoverSuperseded {
			// #9036: FAIL the barrier rather than disarming it. Disarming makes
			// waitFailoverActuated return nil, which the ack path cannot tell
			// from a real fence -- so a request that demoted NOTHING was ACKed
			// `applied` and the peer promoted into a two-owner window, which is
			// exactly #5640's invariant.
			d.failFailoverActuation(rgID, reqID, barrier, cluster.ErrFailoverSuperseded)
			slog.Info("cluster: remote failover superseded by reset; no transfer performed",
				"rg", rgID, "req_id", reqID)
		}
		// #5079: bind an auto-restore lease to this request. If the
		// requester aborts after this ACK (or crashes / loses the fabric)
		// and never sends a commit, electRG restores us when the lease
		// expires so a failed coordinated failover cannot strand us
		// secondary. The matching commit clears the lease.
		d.cluster.ArmRemoteTransferOutLease([]int{rgID}, reqID)
		return nil
	}
	ss.OnRemoteFailoverBatch = func(rgIDs []int, reqID uint64) error {
		for _, rgID := range rgIDs {
			if !d.cluster.IsLocalPrimary(rgID) {
				return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
			}
		}
		slog.Info("cluster: remote batch failover request from peer", "rgs", rgIDs, "req_id", reqID)
		// #5640: arm every member's fence barrier before the batch
		// demotion enqueues its per-RG events.
		barriers := make(map[int]*failoverActuation, len(rgIDs))
		for _, rgID := range rgIDs {
			barriers[rgID] = d.armFailoverActuation(rgID, reqID)
		}
		res, err := d.cluster.ManualFailoverBatch(rgIDs)
		if err != nil {
			for _, rgID := range rgIDs {
				d.disarmFailoverActuation(rgID, reqID, barriers[rgID])
			}
			slog.Warn("cluster: remote batch failover failed", "rgs", rgIDs, "err", err)
			return err
		}
		// #8000: same as the singular path, per skipped member. Without this a
		// PARTIALLY applied batch reported full success here and then failed the
		// applied-ack with a fence timeout on whichever member the reset won —
		// so the operator was told the wrong thing twice, in two different
		// directions, about the same request.
		for _, rgID := range res.Superseded {
			// #9036: same reasoning as the singular path. A superseded MEMBER
			// must not contribute an applied-ack for the batch.
			d.failFailoverActuation(rgID, reqID, barriers[rgID], cluster.ErrFailoverSuperseded)
		}
		if res.Partial() {
			slog.Warn("cluster: remote batch failover partially applied; members superseded by reset",
				"rgs", rgIDs, "applied", res.Applied, "superseded", res.Superseded, "req_id", reqID)
		}
		// #5079: bind auto-restore leases to this request across the set.
		d.cluster.ArmRemoteTransferOutLease(rgIDs, reqID)
		return nil
	}
	ss.OnRemoteFailoverCommit = func(rgID int, reqID uint64) error {
		if err := d.cluster.FinalizePeerTransferOut(rgID); err != nil {
			return err
		}
		// #5079: the transfer committed — drop the auto-restore lease so
		// it can never fire on a legitimately completed handoff.
		d.cluster.ClearRemoteTransferOutLease(rgID, reqID)
		return nil
	}
	ss.OnRemoteFailoverCommitBatch = func(rgIDs []int, reqID uint64) error {
		if err := d.cluster.FinalizePeerTransferOutBatch(rgIDs); err != nil {
			return err
		}
		for _, rgID := range rgIDs {
			d.cluster.ClearRemoteTransferOutLease(rgID, reqID)
		}
		return nil
	}
	// #5640: gate the transfer-out applied-ack on the local demotion
	// actually being actuated (VRRP resigned / rg_active cleared),
	// closing the two-owner window where the peer promoted off an ack
	// sent before this node had resigned.
	ss.WaitFailoverApplied = d.waitFailoverActuated
	ss.WaitFailoverAppliedBatch = d.waitFailoverActuatedBatch
}

// wireClusterPeerFailoverHooks points the cluster Manager at the sync
// connection for outbound remote-failover traffic and installs the local
// readiness/lease/timeout hooks. Extracted verbatim from startClusterComms
// (#6428) — pure code motion.
//
// Order contract: installed before ss.Start, and after ss exists (the hooks
// bind ss method values).
func (d *Daemon) wireClusterPeerFailoverHooks(ss *cluster.SessionSync) {
	// Wire peer failover sender so cluster Manager can send remote
	// failover requests via the fabric sync connection.
	d.cluster.SetPeerFailoverFunc(ss.SendFailover)
	d.cluster.SetPeerFailoverCommitFunc(ss.SendFailoverCommit)
	d.cluster.SetPeerFailoverBatchFunc(ss.SendFailoverBatch)
	d.cluster.SetPeerFailoverCommitBatchFunc(ss.SendFailoverCommitBatch)
	d.cluster.SetPreManualFailoverHook(d.prepareUserspaceManualFailover)
	d.cluster.SetLocalTransferCommitReadyHook(d.waitLocalFailoverCommitReady)
	// #5079: size the owner-side transfer-out lease above the requester's
	// worst-case post-ACK commit latency — the local commit-ready settle
	// window (localFailoverCommitTimeout) plus the commit round-trip — so
	// a legitimate slow commit never trips it. The cluster floors it. The
	// upstream 20s failover-ACK cap (failoverAckTimeout, sync.go) bounds
	// the actuation-barrier contribution: if the owner takes longer than
	// 20s to ack, the requester times out and sends NO commit, so a large
	// failoverActuateTimeout cannot delay a real commit past this lease.
	d.cluster.SetRemoteTransferOutLeaseDuration(2*d.localFailoverCommitTimeout + 20*time.Second)
	d.cluster.SetTransferReadinessFunc(d.userspaceTransferReadiness)
	// #9569: the untargeted failover and ForceSecondary refuse a peer that did
	// not apply the newest config this node sent.
	d.cluster.SetPeerConfigStaleFunc(d.peerConfigStale)
	d.cluster.SetPeerTimeoutGuard(d.shouldSuppressPeerHeartbeatTimeout)
	// #7367: surface the dataplane's view of each RG in the status render.
	d.cluster.SetRGForwardingFunc(d.rgForwardingStatus)
	// #1792: while our heartbeat sockets restart (VRF rebind),
	// keep the peer's suppression guard fed with fresh sync
	// traffic so a >500ms restart does not fire a false
	// peer-timeout/fence on the peer. Bounded by the peer's
	// 5s continuous-suppression cap.
	d.cluster.SetHeartbeatRestartNotifyFunc(ss.SendLivenessKeepalive)
}

// wireClusterFenceCallbacks wires peer fencing in both directions: the
// Manager's outbound fence sender and the inbound fence handler that disables
// every CURRENT redundancy group (#3917). Extracted verbatim from
// startClusterComms (#6428) — pure code motion.
//
// Order contract: installed before ss.Start so an early peer fence cannot
// arrive on an unwired object.
func (d *Daemon) wireClusterFenceCallbacks(commsCtx context.Context, ss *cluster.SessionSync) {
	// Wire peer fencing: on heartbeat timeout, cluster sends
	// fence via sync; on receive, disable all local RGs.
	d.cluster.SetPeerFenceFunc(ss.SendFence)
	// #7147: the CONFIRMED variant of the same outbound fence, used only by
	// `peer-fencing disable-rg-confirmed`. Wired beside the best-effort one
	// because they share a lifecycle; the Manager picks between them off the
	// committed policy, so `disable-rg` still takes the unsequenced path.
	d.cluster.SetPeerFenceConfirmFunc(ss.SendFenceAwait)
	ss.OnFenceReceived = func() cluster.FenceResult {
		slog.Warn("cluster: fence received from peer")
		// #3917: fence the CURRENT redundancy-group set, not the
		// `cfg` snapshot captured in this closure at
		// startClusterComms time. Comms are only restarted on a
		// transport-field change (clusterTransportKey), so a
		// redundancy-group added by a day-2 commit is absent from
		// the startup snapshot. Fencing off the snapshot would
		// leave that RG active on this node while the peer also
		// becomes active for it -> split-brain dual-active. The
		// dp==nil (config-only) and nil-cluster guards live in
		// fenceAllRedundancyGroups.
		return d.fenceAllRedundancyGroups(commsCtx)
	}
}

// wireUserspaceEventStreamForSync installs the userspace event-stream
// callbacks when the published dataplane provides a stream, returning the
// instance the callbacks landed on (nil when none wired). Extracted verbatim
// from startClusterComms (#6428) — pure code motion.
//
// Order contract: MUST run before the ss.Start retry loop — the returned
// stream selects which drain loop that loop launches after a successful Start.
func (d *Daemon) wireUserspaceEventStreamForSync(commsCtx context.Context) *dpuserspace.EventStream {
	// r6-F4: the wiring resolves the provider from the #2114
	// cell per poll, so it never installs callbacks on a backend
	// the daemon has since disowned. wiredStream is the instance
	// the callbacks landed on; the fallback loop re-installs if a
	// rollback + corrected re-arm replaces it.
	var wiredStream *dpuserspace.EventStream
	if _, ok := d.dataplane().(userspaceEventStreamProvider); ok {
		// userspaceEventStreamProvider is a local probe;
		// userspace LegacyDataPlaneAdapter satisfies it via
		// EventStream (legacy_dataplane.go:414). Type-
		// assertion target is the published dataplane directly —
		// the legacyDP() round-trip retired in #1519 added no
		// method-set coverage.
		wireCtx, cancel := context.WithTimeout(commsCtx, 5*time.Second)
		wiredStream = d.wireUserspaceEventStreamCallbacks(wireCtx)
		cancel()
		if wiredStream == nil {
			slog.Warn("userspace: event stream callbacks not ready before session sync start; falling back to polling until stream wires")
		}
	}
	return wiredStream
}

// startClusterSyncAuxLoops starts the comms-scoped auxiliary loops that follow
// the session-sync start attempt: periodic IPsec SA sync, the level-triggered
// config-sync reconcile loop, and the DHCP lease-sync push loop. Extracted
// verbatim from startClusterComms (#6428) — pure code motion.
//
// Order contract: called unconditionally after the ss.Start retry loop, exactly
// as before — these loops still start even when every Start attempt failed.
func (d *Daemon) startClusterSyncAuxLoops(commsCtx context.Context, cc *config.ClusterConfig) {
	// #8967: routed through the idempotent starter so a later
	// `ipsec-sa-synchronization` knob toggle from the apply path shares this
	// same launch/stop path -- the shape the DHCP lease-sync sibling below
	// already uses (#4647). Before this, the knob was read ONCE here at comms
	// start, so enabling it on a running cluster committed successfully and
	// started nothing until an unrelated comms restart.
	d.ensureIPsecSASyncLoop(cc.IPsecSASync)

	// #5863: start the level-triggered config-sync reconcile loop.
	// It is the low-frequency safety net that (a) fires the moment the
	// node crosses the stability threshold and (b) recovers any dropped
	// promotion/connect edge. Started unconditionally (config-sync may
	// be enabled by a later commit without a comms restart); it is a
	// cheap no-op on any node that is not the RG0 config authority or
	// whose current generation is already pushed.
	go d.configSyncReconcileLoop(commsCtx)

	// #2239: start the DHCP-server lease-sync push loop if enabled.
	// The loop is gated on the RG-MASTER node-level gate internally;
	// on the BACKUP it pushes nothing and the standby holds the peer
	// set via OnDHCPLeasesReceived. Routed through the idempotent
	// starter (#4647) so a later `dhcp-lease-synchronization` knob
	// toggle from the apply path shares this same launch/stop path
	// (and cannot double-launch).
	d.ensureDHCPLeaseSyncLoop(cc.DHCPLeaseSync)

	// #8121: push idle persistent-NAT leases on a slow tick. Gated on RG
	// master inside the loop, so a standby never echoes back what it
	// imported. Scoped to the comms context like the loops above.
	go d.runPersistentNatLeaseSyncLoop(commsCtx)
}

// startFabricForwardingLoops starts the fabric_fwd population loops (fab0 and,
// when configured, fab1) plus the netlink fabric-state monitor. Extracted
// verbatim from startClusterComms (#6428) — pure code motion.
//
// Order contract: called only after publishFabricRefreshChansIfCurrent
// succeeded, and each loop is handed its OWN channel by value (#4038/#4958).
func (d *Daemon) startFabricForwardingLoops(commsCtx context.Context, cc *config.ClusterConfig, fabRefreshCh, fabRefreshCh1 chan struct{}) {
	// Populate fabric_fwd BPF map for cross-chassis redirect,
	// then periodically refresh to correct neighbor drift.
	// Resolve to physical parent (ge-0-0-0) — BPF runs on
	// the parent, not the IPVLAN overlay. Neighbor resolution
	// uses the overlay (fab0/fab1) where the sync IP lives (#129).
	fabParent := d.resolveFabricParent(cc.FabricInterface)
	fabOverlay := config.LinuxIfName(cc.FabricInterface)
	if fabOverlay == fabParent {
		fabOverlay = "" // no overlay — legacy mode
	}
	go d.populateFabricFwd(commsCtx, fabParent, fabOverlay, cc.FabricPeerAddress, fabRefreshCh)

	// Populate secondary fabric_fwd entry (key=1) if fab1 configured.
	if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
		fab1Parent := d.resolveFabricParent(cc.Fabric1Interface)
		fab1Overlay := config.LinuxIfName(cc.Fabric1Interface)
		if fab1Overlay == fab1Parent {
			fab1Overlay = "" // no overlay
		}
		go d.populateFabricFwd1(commsCtx, fab1Parent, fab1Overlay, cc.Fabric1PeerAddress, fabRefreshCh1)
	}

	// Monitor fabric link/neighbor state via netlink (#124).
	go d.monitorFabricState(commsCtx)
}
