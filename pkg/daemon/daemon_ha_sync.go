package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

func (d *Daemon) stopSyncReadyTimer() {
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	d.syncReadyTimerGen.Add(1)
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
		d.syncReadyTimer = nil
	}
}

func (d *Daemon) armSyncReadyTimer() {
	if d.cluster == nil || d.syncReadyTimeout <= 0 {
		return
	}
	timerGen := d.syncReadyTimerGen.Add(1)
	d.syncReadyTimerMu.Lock()
	defer d.syncReadyTimerMu.Unlock()
	if d.syncReadyTimer != nil {
		d.syncReadyTimer.Stop()
	}
	timeout := d.syncReadyTimeout
	d.syncReadyTimer = time.AfterFunc(timeout, func() {
		if d.syncReadyTimerGen.Load() != timerGen || !d.syncPeerConnected.Load() {
			return
		}
		if d.cluster != nil && !d.cluster.IsSyncReady() {
			slog.Info("cluster: sync readiness timeout, releasing hold")
			d.cluster.SetSyncReady(true)
		}
	})
}

func (d *Daemon) onSessionSyncPeerConnected() {
	d.syncPeerConnected.Store(true)
	d.hbSuppressStart.Store(0) // fresh connection → reset suppression cap

	// Determine whether this is a true cold start or a routine reconnect.
	// A cold start means no bulk sync has ever completed during this
	// daemon's lifetime — the peer (or we) genuinely started from scratch.
	// On a routine reconnect after a brief network blip, the sessions are
	// already synced; preserve the primed state and sync readiness (#466).
	coldStart := d.sessionSync == nil || !d.sessionSync.BulkEverCompleted()

	if coldStart {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	gen := d.syncPrimeRetryGen.Add(1)
	slog.Info("cluster: session sync peer connected",
		"retry_gen", gen,
		"cold_start", coldStart,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())

	if coldStart {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
		d.armSyncReadyTimer()
		d.startSessionSyncPrimeRetry(gen)
	}
}

func (d *Daemon) onSessionSyncBulkReceived() {
	d.syncBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk received",
		"retry_gen", d.syncPrimeRetryGen.Load())
	d.stopSyncReadyTimer()
	if d.vrrpMgr != nil {
		d.vrrpMgr.ReleaseSyncHold()
	}
	if d.cluster != nil {
		d.cluster.SetSyncReady(true)
	}
}

func (d *Daemon) onSessionSyncBulkAckReceived() {
	d.syncPeerBulkPrimed.Store(true)
	slog.Info("cluster: session sync bulk ack received",
		"retry_gen", d.syncPrimeRetryGen.Load())
}

func (d *Daemon) onSessionSyncPeerDisconnected() {
	d.syncPeerConnected.Store(false)
	gen := d.syncPrimeRetryGen.Add(1)

	// On disconnect after a completed bulk exchange, preserve primed state
	// and sync readiness. The sessions are still in the BPF maps — a
	// subsequent reconnect will resume incremental sync without needing a
	// full bulk transfer (#466).
	wasEverPrimed := d.sessionSync != nil && d.sessionSync.BulkEverCompleted()
	if !wasEverPrimed {
		d.syncBulkPrimed.Store(false)
		d.syncPeerBulkPrimed.Store(false)
	}

	slog.Info("cluster: session sync peer disconnected",
		"retry_gen", gen,
		"was_ever_primed", wasEverPrimed,
		"bulk_primed", d.syncBulkPrimed.Load(),
		"peer_bulk_primed", d.syncPeerBulkPrimed.Load(),
		"cluster_sync_ready", d.cluster != nil && d.cluster.IsSyncReady())
	d.stopSyncReadyTimer()

	if !wasEverPrimed {
		if d.cluster != nil {
			d.cluster.SetSyncReady(false)
		}
	}
}

func (d *Daemon) shouldSuppressPeerHeartbeatTimeout() (bool, string) {
	ss := d.sessionSync
	if ss == nil || !ss.IsConnected() {
		d.hbSuppressStart.Store(0) // reset when sync disconnected
		return false, ""
	}
	const maxPeerSyncSilence = 2 * time.Second
	age, ok := ss.LastPeerReceiveAge()
	if !ok || age > maxPeerSyncSilence {
		d.hbSuppressStart.Store(0) // reset when sync goes quiet
		return false, ""
	}

	// Cap total suppression duration. During graceful shutdown the peer
	// may send a bulk sync that keeps LastPeerReceiveAge() fresh for tens
	// of seconds while heartbeats have already stopped. After 5s of
	// continuous suppression, stop suppressing so the heartbeat timeout
	// can fire and trigger failover.
	const maxSuppressDuration = 5 * time.Second
	now := time.Now().UnixNano()
	start := d.hbSuppressStart.Load()
	if start == 0 {
		d.hbSuppressStart.Store(now)
		start = now
	}
	if time.Duration(now-start) > maxSuppressDuration {
		return false, ""
	}

	return true, fmt.Sprintf("session sync connected with recent peer traffic age=%s", age.Truncate(10*time.Millisecond))
}

func syncPrimeProgressObserved(current, baseline cluster.SyncStatsSnapshot) bool {
	return current.SessionsReceived > baseline.SessionsReceived ||
		current.SessionsInstalled > baseline.SessionsInstalled ||
		current.DeletesReceived > baseline.DeletesReceived
}

func (d *Daemon) startSessionSyncPrimeRetry(gen uint64) {
	ss := d.sessionSync
	if ss == nil || d.dp == nil {
		return
	}
	go func() {
		intervals := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
		const retryWhileAckPendingAfter = 35 * time.Second
		maxAttempts := len(intervals)
		baseline := ss.Stats()
		slog.Info("cluster: starting session sync bulk-prime retry loop",
			"retry_gen", gen,
			"max_attempts", maxAttempts,
			"intervals", intervals)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if wait := intervals[attempt-1]; wait > 0 {
				time.Sleep(wait)
			}
			if d.syncPrimeRetryGen.Load() != gen {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "generation advanced")
				return
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer bulk ack received")
				return
			}
			if d.sessionSync != ss || !ss.IsConnected() {
				reason := "session sync replaced"
				if d.sessionSync == ss && !ss.IsConnected() {
					reason = "session sync disconnected"
				}
				slog.Info("cluster: stopping session sync bulk-prime retry loop",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", reason)
				return
			}
			if pendingEpoch, pendingAge, ok := ss.PendingBulkAck(); ok && pendingAge < retryWhileAckPendingAfter {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "outbound bulk still awaiting ack",
					"pending_epoch", pendingEpoch,
					"pending_age", pendingAge.Round(10*time.Millisecond),
					"retry_after", retryWhileAckPendingAfter)
				continue
			}
			current := ss.Stats()
			if syncPrimeProgressObserved(current, baseline) {
				slog.Info("cluster: deferring session sync bulk-prime retry",
					"retry_gen", gen,
					"attempt", attempt,
					"reason", "peer sync progress observed",
					"sessions_received", current.SessionsReceived,
					"sessions_installed", current.SessionsInstalled,
					"deletes_received", current.DeletesReceived,
					"baseline_sessions_received", baseline.SessionsReceived,
					"baseline_sessions_installed", baseline.SessionsInstalled,
					"baseline_deletes_received", baseline.DeletesReceived)
				baseline = current
				continue
			}
			slog.Info("cluster: retrying session sync bulk prime",
				"retry_gen", gen,
				"attempt", attempt,
				"connected", ss.IsConnected(),
				"sessions_received", current.SessionsReceived,
				"sessions_installed", current.SessionsInstalled,
				"deletes_received", current.DeletesReceived,
				"baseline_sessions_received", baseline.SessionsReceived,
				"baseline_sessions_installed", baseline.SessionsInstalled,
				"baseline_deletes_received", baseline.DeletesReceived)
			if err := d.bulkSyncViaEventStreamOrFallback(ss); err != nil {
				slog.Warn("cluster: session sync bulk prime retry failed",
					"retry_gen", gen,
					"attempt", attempt,
					"err", err)
				continue
			}
			if d.syncPeerBulkPrimed.Load() {
				slog.Info("cluster: session sync bulk prime retry loop observed bulk ack",
					"retry_gen", gen,
					"attempt", attempt)
				return
			}
		}
		slog.Warn("cluster: session sync bulk-prime retry loop exhausted",
			"retry_gen", gen,
			"attempts", maxAttempts)
	}()
}

// bulkSyncViaEventStreamOrFallback attempts to export all sessions via the
// event stream (fast path — sessions flow through the existing event stream
// callback into QueueSessionV4/V6). Falls back to the old BulkSync path
// (iterating BPF maps from Go) when the event stream isn't available.
func (d *Daemon) bulkSyncViaEventStreamOrFallback(ss *cluster.SessionSync) error {
	if exporter, ok := d.legacyDP().(userspaceEventStreamExporter); ok {
		slog.Info("cluster: using event stream export for bulk sync")
		if err := exporter.ExportAllSessionsViaEventStream(); err != nil {
			slog.Warn("cluster: event stream bulk export failed, falling back to BulkSync", "err", err)
		} else {
			slog.Info("cluster: exported sessions via event stream for bulk sync")
			return nil
		}
	}
	slog.Info("cluster: event stream export not available, falling back to BulkSync",
		"dp_type", fmt.Sprintf("%T", d.legacyDP()))
	if ss == nil {
		return fmt.Errorf("session sync not initialized")
	}
	return ss.BulkSync()
}

// syncConfigToPeer sends the active config to the cluster peer if this node
// is primary and config sync is enabled.
func (d *Daemon) syncConfigToPeer() {
	if d.cluster == nil || d.sessionSync == nil {
		return
	}
	// Only sync if this node is primary for RG0 (config ownership group).
	if !d.cluster.IsLocalPrimary(0) {
		return
	}
	d.pushConfigToPeer()
}

// pushConfigToPeer sends the active config to the cluster peer unconditionally
// (does not check primary/secondary status). Used both by normal commit sync
// and by the peer-reconnect path where the stable node pushes its config
// regardless of whether it was preempted.
func (d *Daemon) pushConfigToPeer() {
	if d.sessionSync == nil {
		return
	}
	// Check if config sync is enabled.
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.ConfigSync {
		return
	}
	// Get the active config tree as text.
	configText := d.store.ShowActive()
	if configText == "" {
		return
	}
	d.sessionSync.QueueConfig(configText)
}

// handleConfigSync processes a config received from the cluster peer.
// Config sync is unidirectional: primary → secondary only. If this node
// is the RG0 primary (config authority), incoming config is rejected to
// prevent a reconnecting secondary from overwriting the authoritative config.
func (d *Daemon) handleConfigSync(configText string) {
	if d.cluster != nil && d.cluster.IsLocalPrimary(0) {
		slog.Warn("cluster: rejecting config sync (this node is RG0 primary)")
		return
	}
	if d.store != nil {
		activeText := strings.TrimSpace(d.store.ShowActive())
		incomingText := strings.TrimSpace(configText)
		if activeText == incomingText {
			slog.Info("cluster: skipping config sync apply (config already matches active)",
				"size", len(configText))
			return
		}
	}
	slog.Info("cluster: accepting config sync from peer", "size", len(configText))

	// #846: route through syncAndApply so the peer's
	// SyncApply(active promotion) + applyConfig run atomically
	// under d.applySem. Without this, a local commitAndApply could
	// interleave between the two and briefly leave store and kernel
	// disagreeing.
	if _, err := d.syncAndApply(context.Background(), configText, nil); err != nil {
		slog.Error("cluster: config sync apply failed", "err", err)
		return
	}
	slog.Info("cluster: config sync applied successfully")
}

// watchClusterEvents monitors cluster state transitions and toggles
// config store read-only mode based on primary/secondary state.
// startClusterComms starts heartbeat and session sync after VRFs are created.
// Called after applyConfig so that control/fabric interfaces are already in
// the management VRF (if configured).
func (d *Daemon) startClusterComms(ctx context.Context) {
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	cc := cfg.Chassis.Cluster

	// Create an independently-cancellable sub-context so cluster comms can
	// be restarted on config change (#87) without cancelling the daemon ctx.
	commsCtx, commsCancel := context.WithCancel(ctx)
	d.clusterCommsCancel = commsCancel
	d.activeClusterTransport = clusterTransportFromConfig(cfg)

	// Determine VRF device if control/fabric interfaces are in mgmt VRF.
	// Check mgmtVRFInterfaces first, then fall back to probing the control
	// interface directly (handles config-only mode where applyConfig may
	// have run but mgmtVRFInterfaces is empty due to VRF creation failure).
	vrfDevice := ""
	if len(d.mgmtVRFInterfaces) > 0 {
		vrfDevice = "vrf-mgmt"
	} else if cc.ControlInterface != "" {
		// Control/fabric interfaces (em*, fab*) are always placed in
		// vrf-mgmt by the compiler. Check if the VRF device exists.
		if _, err := net.InterfaceByName("vrf-mgmt"); err == nil {
			vrfDevice = "vrf-mgmt"
		}
	}

	// Start BPF watchdog heartbeat: write monotonic timestamp to ha_watchdog
	// map every 500ms for each configured RG. If the daemon is SIGKILL'd,
	// the timestamp goes stale and BPF stops forwarding within 2s.
	if d.dp != nil && len(cc.RedundancyGroups) > 0 {
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-commsCtx.Done():
					return
				case <-ticker.C:
					var ts unix.Timespec
					_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
					now := uint64(ts.Sec)
					for _, rg := range cc.RedundancyGroups {
						if err := d.dp.HA().SetHAWatchdog(commsCtx, rg.ID, now); err != nil {
							slog.Warn("ha watchdog write failed", "rg", rg.ID, "err", err)
						}
					}
				}
			}
		}()
		slog.Info("HA watchdog heartbeat started", "rgs", len(cc.RedundancyGroups))
	}

	// In VRRP mode, make strict VIP ownership the runtime default so
	// rg_active follows VIP/MAC ownership rather than cluster-primary
	// intent. Direct/no-reth-vrrp mode and private-rg-election mode
	// still use cluster state because there are no VRRP instances to
	// gate on.
	d.syncRGStrictVIPOwnershipMode(cc)

	// Start heartbeat if control-interface and peer-address are configured.
	// Retry on bind failure: the control interface address and VRF device
	// may not be ready during daemon startup (networkd race).
	if cc.ControlInterface != "" && cc.PeerAddress != "" {
		go func() {
			for i := 0; i < 30; i++ {
				localIP := resolveClusterInterfaceAddr(cc.ControlInterface, cc.PeerAddress, "")
				if localIP == "" {
					if i == 0 {
						slog.Info("cluster: control interface has no usable address yet, waiting",
							"interface", cc.ControlInterface)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				if err := d.cluster.StartHeartbeat(localIP, cc.PeerAddress, vrfDevice); err != nil {
					if i < 5 {
						slog.Info("cluster: heartbeat bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start cluster heartbeat, retrying",
							"err", err, "attempt", i+1)
					}
					time.Sleep(2 * time.Second)
					continue
				}
				return
			}
			slog.Error("cluster heartbeat failed after retries")
		}()
	}

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
	if syncIface != "" && syncPeerAddr != "" {
		go func() {
			var syncIP string
			for i := 0; i < 30; i++ {
				syncIP = resolveClusterInterfaceAddr(syncIface, syncPeerAddr, "")
				if syncIP != "" {
					break
				}
				if i == 0 {
					slog.Info("cluster: sync interface has no usable address yet, waiting",
						"interface", syncIface, "transport", syncTransport)
				}
				select {
				case <-commsCtx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			if syncIP == "" {
				slog.Error("cluster: sync interface address not available after retries",
					"interface", syncIface)
				return
			}

			syncLocal := net.JoinHostPort(syncIP, "4785")
			syncPeer := net.JoinHostPort(syncPeerAddr, "4785")
			slog.Info("cluster: session sync transport", "mode", syncTransport,
				"local", syncLocal, "peer", syncPeer)

			// Resolve secondary fabric (fab1) for dual transport failover.
			// Only applicable when using fabric transport (not control-link).
			var syncLocal1, syncPeer1 string
			if syncTransport == "fabric" && cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				var fab1IP string
				for i := 0; i < 15; i++ {
					fab1IP = resolveClusterInterfaceAddr(cc.Fabric1Interface, cc.Fabric1PeerAddress, "")
					if fab1IP != "" {
						break
					}
					if i == 0 {
						slog.Info("cluster: fabric1 interface has no usable address yet, waiting",
							"interface", cc.Fabric1Interface)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
				if fab1IP != "" {
					syncLocal1 = net.JoinHostPort(fab1IP, "4785")
					syncPeer1 = net.JoinHostPort(cc.Fabric1PeerAddress, "4785")
					slog.Info("cluster: dual fabric transport configured",
						"fab0_local", syncLocal, "fab1_local", syncLocal1)
				} else {
					slog.Warn("cluster: fabric1 address not available, using single fabric only",
						"interface", cc.Fabric1Interface)
				}
			}

			if syncLocal1 != "" {
				d.sessionSync = cluster.NewDualSessionSync(syncLocal, syncPeer, syncLocal1, syncPeer1, nil)
			} else {
				d.sessionSync = cluster.NewSessionSync(syncLocal, syncPeer, nil)
			}

			d.cluster.SetSyncTransport(syncTransport)

			// Store sync peer addresses for gRPC peer dialing (session queries etc).
			d.syncPeerAddr = syncPeerAddr
			if syncLocal1 != "" {
				d.syncPeerAddr1 = cc.Fabric1PeerAddress
			}

			// Start gRPC fabric listener(s) so peer can proxy monitor requests.
			// d.grpcSrv is set after startClusterComms returns, so we poll briefly.
			// Uses the sync interface address (fabric or control-link).
			// When dual-fabric is configured, listen on both fabric IPs.
			go func() {
				for i := 0; i < 30; i++ {
					if d.grpcSrv != nil {
						grpcAddr := fmt.Sprintf("%s:50051", syncIP)
						if syncLocal1 != "" {
							// Extract fab1 local IP (syncLocal1 is "ip:4785").
							fab1Host, _, _ := net.SplitHostPort(syncLocal1)
							grpcAddr1 := fmt.Sprintf("%s:50051", fab1Host)
							go d.grpcSrv.RunFabricListener(commsCtx, grpcAddr1, vrfDevice)
							slog.Info("gRPC dual fabric listeners", "fab0", grpcAddr, "fab1", grpcAddr1)
						}
						d.grpcSrv.RunFabricListener(commsCtx, grpcAddr, vrfDevice)
						return
					}
					time.Sleep(time.Second)
				}
			}()

			// Wire sync stats into cluster manager for CLI display.
			d.cluster.SetSyncStats(d.sessionSync)

			// Wire config sync callback: when secondary receives config from primary.
			d.sessionSync.OnConfigReceived = func(configText string) {
				d.cluster.RecordEvent(cluster.EventConfigSync, -1, fmt.Sprintf("Config received (%d bytes)", len(configText)))
				d.handleConfigSync(configText)
			}

			// Wire peer connected callback: push config to returning peer.
			// Only push if this node is RG0 primary (config authority) and
			// has been running >30s (stable node). A freshly started node
			// must NOT push stale config from disk.
			d.sessionSync.OnPeerConnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer connected")
				d.onSessionSyncPeerConnected()
				if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
					slog.Info("cluster: skipping config push (not RG0 primary)")
					return
				}
				if time.Since(d.startTime) < 30*time.Second {
					slog.Info("cluster: skipping config push (daemon just started)")
					return
				}
				slog.Info("cluster: pushing config to reconnected peer")
				d.pushConfigToPeer()
			}

			d.sessionSync.OnBulkSyncReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync completed")
				slog.Info("cluster: session sync complete, releasing VRRP hold")
				d.onSessionSyncBulkReceived()
			}

			d.sessionSync.OnBulkSyncAckReceived = func() {
				d.cluster.RecordEvent(cluster.EventColdSync, -1, "Bulk sync acknowledged by peer")
				d.onSessionSyncBulkAckReceived()
			}

			d.sessionSync.OnForwardSessionInstalled = func() {
				d.scheduleStandbyNeighborRefresh()
			}

			// Wire bulk sync override: use event stream export (fast path)
			// instead of BPF map iteration for initial bulk sync on connect.
			d.sessionSync.BulkSyncOverride = func() error {
				return d.bulkSyncViaEventStreamOrFallback(d.sessionSync)
			}

			d.sessionSync.OnPeerDisconnected = func() {
				d.cluster.RecordEvent(cluster.EventFabric, -1, "Peer disconnected (all fabrics)")
				d.onSessionSyncPeerDisconnected()
			}

			// Wire remote failover: when the peer requests us to transfer an RG
			// out of primary and explicitly acknowledge the result.
			// Guard: only honor the request if we are actually primary for
			// this RG. Stale/delayed sync messages can arrive after we've
			// already transitioned to secondary — blindly calling
			// ManualFailover would cause dual-resign (both nodes secondary)
			// and a 30-second traffic blackhole.
			d.sessionSync.OnRemoteFailover = func(rgID int) error {
				if !d.cluster.IsLocalPrimary(rgID) {
					return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
				}
				slog.Info("cluster: remote failover request from peer", "rg", rgID)
				if err := d.cluster.ManualFailover(rgID); err != nil {
					slog.Warn("cluster: remote failover failed", "rg", rgID, "err", err)
					return err
				}
				return nil
			}
			d.sessionSync.OnRemoteFailoverBatch = func(rgIDs []int) error {
				for _, rgID := range rgIDs {
					if !d.cluster.IsLocalPrimary(rgID) {
						return fmt.Errorf("%w: redundancy group %d", cluster.ErrRemoteFailoverRejected, rgID)
					}
				}
				slog.Info("cluster: remote batch failover request from peer", "rgs", rgIDs)
				if err := d.cluster.ManualFailoverBatch(rgIDs); err != nil {
					slog.Warn("cluster: remote batch failover failed", "rgs", rgIDs, "err", err)
					return err
				}
				return nil
			}
			d.sessionSync.OnRemoteFailoverCommit = func(rgID int) error {
				return d.cluster.FinalizePeerTransferOut(rgID)
			}
			d.sessionSync.OnRemoteFailoverCommitBatch = func(rgIDs []int) error {
				return d.cluster.FinalizePeerTransferOutBatch(rgIDs)
			}

			// Wire peer failover sender so cluster Manager can send remote
			// failover requests via the fabric sync connection.
			d.cluster.SetPeerFailoverFunc(d.sessionSync.SendFailover)
			d.cluster.SetPeerFailoverCommitFunc(d.sessionSync.SendFailoverCommit)
			d.cluster.SetPeerFailoverBatchFunc(d.sessionSync.SendFailoverBatch)
			d.cluster.SetPeerFailoverCommitBatchFunc(d.sessionSync.SendFailoverCommitBatch)
			d.cluster.SetPreManualFailoverHook(d.prepareUserspaceManualFailover)
			d.cluster.SetLocalTransferCommitReadyHook(d.waitLocalFailoverCommitReady)
			d.cluster.SetTransferReadinessFunc(d.userspaceTransferReadiness)
			d.cluster.SetPeerTimeoutGuard(d.shouldSuppressPeerHeartbeatTimeout)

			// Wire peer fencing: on heartbeat timeout, cluster sends
			// fence via sync; on receive, disable all local RGs.
			d.cluster.SetPeerFenceFunc(d.sessionSync.SendFence)
			d.sessionSync.OnFenceReceived = func() {
				slog.Warn("cluster: fence received from peer, disabling all RGs")
				if cfg.Chassis.Cluster != nil {
					for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
						if err := d.dp.HA().SetRGActive(commsCtx, rg.ID, false); err != nil {
							slog.Warn("cluster: fence: failed to disable rg_active",
								"rg", rg.ID, "err", err)
						}
					}
				}
			}

			d.sessionSync.SetVRFDevice(vrfDevice)
			var streamProvider userspaceEventStreamProvider
			streamCallbacksWired := false
			if d.dp != nil {
				if provider, ok := d.legacyDP().(userspaceEventStreamProvider); ok {
					streamProvider = provider
					wireCtx, cancel := context.WithTimeout(commsCtx, 5*time.Second)
					streamCallbacksWired = d.wireUserspaceEventStreamCallbacks(wireCtx, provider)
					cancel()
					if !streamCallbacksWired {
						slog.Warn("userspace: event stream callbacks not ready before session sync start; falling back to polling until stream wires")
					}
				}
			}

			// Retry sync start: the VRF device and address binding may not
			// be ready during daemon startup (networkd race).
			for i := 0; i < 30; i++ {
				if err := d.sessionSync.Start(commsCtx); err != nil {
					if i < 5 {
						slog.Info("cluster: sync bind not ready, retrying",
							"err", err, "attempt", i+1)
					} else {
						slog.Warn("failed to start session sync, retrying",
							"err", err, "attempt", i+1)
					}
					select {
					case <-commsCtx.Done():
						return
					case <-time.After(2 * time.Second):
					}
					continue
				}
				slog.Info("cluster session sync started",
					"local", syncLocal, "peer", syncPeer, "vrf", vrfDevice)

				// Wire dataplane into session sync and start the sweep.
				// Must happen here (not in Run) because d.sessionSync is
				// created asynchronously in this goroutine.
				if d.dp != nil {
					d.sessionSync.SetDataPlane(d.legacyDP())
					d.sessionSync.IsPrimaryFn = func() bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(0)
					}
					d.sessionSync.IsPrimaryForRGFn = func(rgID int) bool {
						return d.cluster != nil && d.cluster.IsLocalPrimary(rgID)
					}
					d.sessionSync.StartSyncSweep(commsCtx)
					if streamCallbacksWired {
						go d.eventStreamFallbackLoop(commsCtx, streamProvider)
					} else {
						go d.runUserspaceEventStream(commsCtx)
					}
				}

				break
			}

			// Start periodic IPsec SA sync if enabled.
			if cc.IPsecSASync && d.ipsec != nil {
				go d.syncIPsecSAPeriodic(commsCtx)
			}

			// Initialize fabric refresh channel for event-driven updates (#124).
			d.fabricRefreshCh = make(chan struct{}, 1)

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
			go d.populateFabricFwd(commsCtx, fabParent, fabOverlay, cc.FabricPeerAddress)

			// Populate secondary fabric_fwd entry (key=1) if fab1 configured.
			if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress != "" {
				fab1Parent := d.resolveFabricParent(cc.Fabric1Interface)
				fab1Overlay := config.LinuxIfName(cc.Fabric1Interface)
				if fab1Overlay == fab1Parent {
					fab1Overlay = "" // no overlay
				}
				go d.populateFabricFwd1(commsCtx, fab1Parent, fab1Overlay, cc.Fabric1PeerAddress)
			}

			// Monitor fabric link/neighbor state via netlink (#124).
			go d.monitorFabricState(commsCtx)
		}()
	}
}

// stopClusterComms tears down heartbeat and session sync so they can be
// restarted with new transport settings (#87). Cancels the comms sub-context
// (which stops retry loops, fabric_fwd refresh, IPsec SA sync, sync sweep)
// and explicitly stops heartbeat + session sync listeners/connections.
func (d *Daemon) stopClusterComms() {
	if d.clusterCommsCancel != nil {
		d.clusterCommsCancel()
		d.clusterCommsCancel = nil
	}
	if d.cluster != nil {
		d.cluster.StopHeartbeat()
	}
	if d.sessionSync != nil {
		d.stopSyncReadyTimer()
		d.sessionSync.Stop()
		d.sessionSync = nil
	}
}

// clusterTransportKey extracts the four cluster transport fields that
// determine heartbeat and session sync endpoints. Used to detect config
// changes that require restarting cluster comms.
type clusterTransportKey struct {
	ControlInterface   string
	PeerAddress        string
	FabricInterface    string
	FabricPeerAddress  string
	Fabric1Interface   string
	Fabric1PeerAddress string
}

func clusterTransportFromConfig(cfg *config.Config) clusterTransportKey {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return clusterTransportKey{}
	}
	cc := cfg.Chassis.Cluster
	return clusterTransportKey{
		ControlInterface:   cc.ControlInterface,
		PeerAddress:        cc.PeerAddress,
		FabricInterface:    cc.FabricInterface,
		FabricPeerAddress:  cc.FabricPeerAddress,
		Fabric1Interface:   cc.Fabric1Interface,
		Fabric1PeerAddress: cc.Fabric1PeerAddress,
	}
}
