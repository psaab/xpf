package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/vrrp"
)

// getOrCreateRGState returns the rgStateMachine for the given RG, creating
// one if it doesn't exist yet.
func (d *Daemon) getOrCreateRGState(rgID int) *rgStateMachine {
	d.rgStatesMu.RLock()
	s, ok := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if ok {
		return s
	}
	d.rgStatesMu.Lock()
	defer d.rgStatesMu.Unlock()
	// Double-check after upgrading to write lock.
	if s, ok = d.rgStates[rgID]; ok {
		return s
	}
	s = newRGStateMachine()
	d.rgStates[rgID] = s
	return s
}

func (d *Daemon) syncRGStrictVIPOwnershipMode(cc *config.ClusterConfig) {
	if cc == nil {
		return
	}
	var cfg *config.Config
	if d.store != nil {
		cfg = d.store.ActiveConfig()
	}
	strictByDefault := strictVIPOwnershipByDefault(cc, cfg)
	for _, rg := range cc.RedundancyGroups {
		s := d.getOrCreateRGState(rg.ID)
		s.SetStrictVIPOwnership(strictByDefault)
	}
}

func strictVIPOwnershipByDefault(cc *config.ClusterConfig, cfg *config.Config) bool {
	if cc == nil {
		return false
	}
	if cc.NoRethVRRP || cc.PrivateRGElection {
		return false
	}
	// In the userspace dataplane, hot standby depends on the future owner
	// already being forwarding-ready before VIP/MAC ownership moves. Waiting
	// for the VRRP MASTER event to derive rg_active leaves a cutover window
	// where reply packets can hit the promoted node before userspace is active.
	return cfg == nil || cfg.System.DataplaneType != dataplane.TypeUserspace
}

func (d *Daemon) setLocalFailoverCommitReady(rgID int, ready bool) {
	d.localFailoverCommitMu.Lock()
	defer d.localFailoverCommitMu.Unlock()
	if d.localFailoverCommitReady == nil {
		d.localFailoverCommitReady = make(map[int]bool)
	}
	d.localFailoverCommitReady[rgID] = ready
}

func (d *Daemon) localFailoverCommitIsReady(rgID int) bool {
	d.localFailoverCommitMu.Lock()
	defer d.localFailoverCommitMu.Unlock()
	if d.localFailoverCommitReady == nil {
		return false
	}
	return d.localFailoverCommitReady[rgID]
}

func recordRGActiveAppliedIfCurrentOrStable(s *rgStateMachine, tr rgTransition, active bool) bool {
	if s.ApplyIfCurrent(tr) {
		return true
	}
	current, _ := s.CurrentDesired()
	if current != active {
		return false
	}
	s.MarkApplied(active)
	return true
}

func (d *Daemon) waitLocalFailoverCommitReady(rgIDs []int) error {
	if len(rgIDs) == 0 {
		return nil
	}
	timeout := d.localFailoverCommitTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	delay := d.localFailoverCommitDelay
	deadline := time.Now().Add(timeout)
	dwelled := false
	for {
		ready := true
		for _, rgID := range rgIDs {
			if d.cluster != nil && !d.cluster.IsLocalPrimary(rgID) {
				return fmt.Errorf("local redundancy group %d lost primary before peer demotion commit", rgID)
			}
			if !d.localFailoverCommitIsReady(rgID) {
				ready = false
				break
			}
		}
		if ready {
			if !dwelled && delay > 0 {
				dwelled = true
				time.Sleep(delay)
				continue
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for local failover activation settle for redundancy groups %v", rgIDs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// isRethMasterState returns true when ALL VRRP instances for rgID are MASTER.
// Returns false if no instances exist for the RG.
func (d *Daemon) isRethMasterState(rgID int) bool {
	return d.getOrCreateRGState(rgID).AllVRRPMaster()
}

// isAnyRethInstanceMaster returns true if ANY VRRP instance for rgID is
// MASTER. Used by the cluster event handler to defer rg_active deactivation
// until all VRRP instances have transitioned to BACKUP.
func (d *Daemon) isAnyRethInstanceMaster(rgID int) bool {
	return d.getOrCreateRGState(rgID).AnyVRRPMaster()
}

// snapshotRethMasterState returns per-RG master state derived from all
// per-instance entries. An RG is MASTER only when ALL its instances are MASTER.
func (d *Daemon) snapshotRethMasterState() map[int]bool {
	d.rgStatesMu.RLock()
	defer d.rgStatesMu.RUnlock()
	out := make(map[int]bool, len(d.rgStates))
	for rgID, s := range d.rgStates {
		out[rgID] = s.IsActive()
	}
	return out
}

func (d *Daemon) watchClusterEvents(ctx context.Context) {
	// Debounce VRRP updates: coalesce rapid cluster events into a single
	// UpdateInstances call. Without this, every heartbeat-driven state change
	// triggers a separate update before priorities settle.
	var vrrpTimer *time.Timer
	defer func() {
		if vrrpTimer != nil {
			vrrpTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.cluster.Events():
			noRethVRRP := d.isNoRethVRRP()

			// Dual-active winner reaffirm: no state change but send
			// GARPs to refresh upstream ARP/NDP caches after split-brain.
			if ev.DualActiveWin && noRethVRRP {
				d.scheduleDirectAnnounce(ev.GroupID, "dual-active-win")
				continue
			}

			// Update rg_active through unified state machine.
			//
			// Both cluster and VRRP events funnel through rgStateMachine
			// which determines rg_active = clusterPri || anyVrrpMaster.
			// This prevents the dual-inactive window (both nodes
			// rg_active=false during failover) and eliminates the race
			// between the two independent goroutine writers.
			//
			// Transition ordering safety:
			// - Activation: set rg_active FIRST, then remove blackholes,
			//   then trigger VRRP MASTER (#485). Neighbor readiness is
			//   maintained continuously in the background.
			// - Deactivation: run preflight FIRST, then resign VRRP,
			//   add blackholes, then clear rg_active (#485)
			isPrimary := ev.NewState == cluster.StatePrimary
			clusterDemotionEdge := ev.OldState == cluster.StatePrimary && !isPrimary
			d.setLocalFailoverCommitReady(ev.GroupID, false)
			s := d.getOrCreateRGState(ev.GroupID)
			tr := s.SetCluster(isPrimary)
			if isPrimary {
				// Activation: enable forwarding first.
				// Re-read desired state to guard against a
				// concurrent VRRP goroutine that may have
				// already superseded this transition.
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if err := d.dp.HA().SetRGActive(ctx, ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
					}
				}
				// Only remove blackholes once this node's desired state is
				// actually active. In strict VIP ownership mode, a cluster
				// primary event alone does not activate the RG until VRRP
				// ownership has moved as well.
				if shouldRemoveBlackholesOnClusterPrimary(s) {
					d.removeBlackholeRoutes(ev.GroupID)
				}

				// VRRP priority + ForceRGMaster AFTER rg_active and
				// blackhole removal (#485).
				if !noRethVRRP {
					d.vrrpMgr.UpdateRGPriority(ev.GroupID, 200)
					// With preempt=false, VRRP won't self-elect even at
					// higher priority. Force MASTER since cluster state
					// is authoritative (e.g. after failover reset).
					// Only do this for intentional promotions (Secondary →
					// Primary), NOT on initial boot (SecondaryHold → Primary)
					// where VRRP should follow its own election timer.
					if ev.OldState == cluster.StateSecondary {
						d.vrrpMgr.ForceRGMaster(ev.GroupID)
					}
				}

				// no-reth-vrrp direct mode: reconcile VIP ownership from
				// actual cluster local/peer state, not just this rg_active
				// edge. This prevents stale VIPs from surviving a demotion
				// when the rg_state machine has already drifted inactive.
				if noRethVRRP {
					d.reconcileDirectVIPOwnership(ev.GroupID, "cluster-primary")
					go d.RefreshFabricFwd()
				}
				if noRethVRRP && d.cluster != nil && d.cluster.IsLocalPrimary(ev.GroupID) && (d.dp == nil || !s.NeedsApply()) {
					d.setLocalFailoverCommitReady(ev.GroupID, true)
				}
			} else {
				// Demotion: run preflight and resign VRRP BEFORE
				// clearing rg_active (#485). The preflight shifts
				// userspace flow cache entries to FabricRedirect so
				// the demoting node forwards via fabric during the
				// transition window. ResignRG must follow preflight
				// so traffic is already on the fabric path before
				// the VRRP BACKUP transition removes VIPs.
				if clusterDemotionEdge && d.dp != nil {
					d.tryPrepareUserspaceRGDemotion(ev.GroupID)
				}
				if !noRethVRRP {
					if ev.OldState == cluster.StatePrimary &&
						(ev.NewState == cluster.StateSecondary || ev.NewState == cluster.StateSecondaryHold) {
						d.vrrpMgr.ResignRG(ev.GroupID)
					}
				}
				// Deactivation: blackhole routes first (if transitioning
				// to inactive), then clear rg_active.
				if tr.Changed && !tr.Active {
					d.injectBlackholeRoutes(ev.GroupID)
				}
				if tr.Changed && d.dp != nil {
					cur, _ := s.CurrentDesired()
					if !cur && !clusterDemotionEdge {
						d.tryPrepareUserspaceRGDemotion(ev.GroupID)
					}
					if err := d.dp.HA().SetRGActive(ctx, ev.GroupID, cur); err != nil {
						slog.Warn("failed to update rg_active from cluster event",
							"rg", ev.GroupID, "active", cur, "err", err)
					} else {
						recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
					}
				}

				// no-reth-vrrp direct mode: always reconcile actual VIP
				// ownership on non-primary transitions. Removal must not
				// depend on a fresh rg_active edge because stale VIPs can
				// survive a failback if the state machine already drifted.
				if noRethVRRP {
					d.reconcileDirectVIPOwnership(ev.GroupID, "cluster-secondary")
				}
			}

			// Strict VIP ownership: suppress GARP on secondary, allow on primary.
			// Not applicable with no-reth-vrrp (no VRRP instances).
			if !noRethVRRP && s.IsStrictVIPOwnership() {
				d.vrrpMgr.SetGARPSuppression(ev.GroupID, !isPrimary)
			}

			// Debounced VRRP priority update — 500ms coalesce window.
			// Skipped in no-reth-vrrp mode (no RETH VRRP instances to update).
			if !noRethVRRP {
				if vrrpTimer != nil {
					vrrpTimer.Stop()
				}
				vrrpTimer = time.AfterFunc(500*time.Millisecond, func() {
					if cfg := d.store.ActiveConfig(); cfg != nil {
						localPri := d.cluster.LocalPriorities()
						var all []*vrrp.Instance
						all = append(all, vrrp.CollectInstances(cfg)...)
						all = append(all, vrrp.CollectRethInstances(cfg, localPri)...)
						if err := d.vrrpMgr.UpdateInstances(all); err != nil {
							slog.Warn("cluster: failed to update VRRP instances", "err", err)
						}
					}
				})
			}

			// RG0-specific: config ownership and IPsec SA re-initiation.
			if ev.GroupID == 0 {
				switch ev.NewState {
				case cluster.StatePrimary:
					slog.Info("cluster: became primary for RG0, enabling config writes")
					d.store.SetClusterReadOnly(false)

					// On failover to primary: re-initiate synced IPsec SAs.
					if cc := d.clusterConfig(); cc != nil && cc.IPsecSASync && d.ipsec != nil && d.sessionSync != nil {
						go d.reinitiateIPsecSAs()
					}

				case cluster.StateSecondary, cluster.StateSecondaryHold:
					slog.Info("cluster: became secondary for RG0, disabling config writes")
					d.store.SetClusterReadOnly(true)
				}
			}
		}
	}
}

// rethVRIDBase is the VRRP GroupID offset for RETH instances.
// RETH instances use GroupID = rethVRIDBase + rgID (set in pkg/vrrp/vrrp.go).
// Standalone VRRP groups use GroupID < rethVRIDBase.
const rethVRIDBase = 100

// isRethVRID returns true if the VRRP GroupID belongs to a RETH instance.
func isRethVRID(vrid int) bool {
	return vrid >= rethVRIDBase
}

// rgIDFromVRID extracts the redundancy group ID from a VRRP group ID.
// VRID = rethVRIDBase + RG ID (set in pkg/vrrp/vrrp.go).
func rgIDFromVRID(vrid int) int {
	return vrid - rethVRIDBase
}

// watchVRRPEvents monitors VRRP state changes and logs transitions.
// On MASTER transition, updates rg_active, removes blackhole routes, and
// refreshes fabric forwarding. Neighbor readiness is maintained in the
// background by runPeriodicNeighborResolution / maintainClusterNeighborReadiness.
// Also starts/stops RA senders and Kea DHCP server per-RG — in
// active/active mode, a BACKUP event for RG1 must not clear services
// started for RG0.
func (d *Daemon) watchVRRPEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-d.vrrpMgr.Events():
			if !ok {
				return
			}
			// Standalone VRRP instances (GroupID < rethVRIDBase) do not
			// participate in HA redundancy group state. Skip the
			// rg_active/blackhole logic to avoid creating phantom RG entries.
			if !isRethVRID(ev.GroupID) {
				slog.Info("vrrp: standalone state change (non-RETH)",
					"interface", ev.Interface,
					"group", ev.GroupID,
					"state", ev.State.String())
				continue
			}
			rgID := rgIDFromVRID(ev.GroupID)
			slog.Info("vrrp: state change",
				"interface", ev.Interface,
				"group", ev.GroupID,
				"rg", rgID,
				"state", ev.State.String())
			if ev.State == vrrp.StateMaster {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, true)
				if tr.Changed && tr.Active && d.dp != nil {
					// Activation order: set rg_active FIRST, then
					// remove blackhole routes. Re-read desired state
					// to guard against interleaved cluster goroutine.
					// Only activate when ALL VRRP instances in the RG
					// are MASTER — prevents partial ownership (#132).
					cur, _ := s.CurrentDesired()
					if err := d.dp.HA().SetRGActive(ctx, rgID, cur); err != nil {
						slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
					} else {
						recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
					}
					go d.RefreshFabricFwd()
				}
				// Only remove blackholes and apply services when ALL
				// VRRP instances in the RG are MASTER (#132).
				if tr.Changed && tr.Active {
					d.removeBlackholeRoutes(rgID)
					d.addStableRethLinkLocal(rgID)
					d.applyRethServicesForRG(rgID)
				}
				if d.cluster != nil && d.cluster.IsLocalPrimary(rgID) && s.AllVRRPMaster() {
					d.setLocalFailoverCommitReady(rgID, true)
				}
			}
			if ev.State == vrrp.StateBackup {
				s := d.getOrCreateRGState(rgID)
				tr := s.SetVRRP(ev.Interface, false)
				if !s.AllVRRPMaster() {
					d.setLocalFailoverCommitReady(rgID, false)
				}
				if tr.Changed && !tr.Active {
					// Deactivation order: inject blackhole routes FIRST,
					// then clear rg_active. Re-read desired state to
					// guard against interleaved cluster goroutine.
					d.injectBlackholeRoutes(rgID)
					if d.dp != nil {
						cur, _ := s.CurrentDesired()
						if !cur {
							d.tryPrepareUserspaceRGDemotion(rgID)
						}
						if err := d.dp.HA().SetRGActive(ctx, rgID, cur); err != nil {
							slog.Warn("failed to update rg_active", "rg", rgID, "err", err)
						} else {
							recordRGActiveAppliedIfCurrentOrStable(s, tr, cur)
						}
						go d.RefreshFabricFwd()
					}
					d.removeStableRethLinkLocal(rgID)
					d.clearRethServicesForRG(rgID)
				}
			}
		}
	}
}

// reconcileRGStateLoop periodically reads the authoritative cluster and VRRP
// states and reconciles rgStateMachine / rg_active BPF map / blackhole routes /
// VRRP posture / RA+DHCP services.
// This is the safety net for dropped events (non-blocking channel sends).
// Runs every 2s; also wakes immediately on event-drop notifications via
// reconcileNowCh. Skips if cluster or dataplane is nil.
func (d *Daemon) reconcileRGStateLoop(ctx context.Context) {
	// Run immediately on startup to correct stale rg_active from prior run.
	d.reconcileRGState()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reconcileRGState()
		case <-d.reconcileNowCh:
			d.reconcileRGState()
		}
	}
}

// triggerReconcile requests an immediate RG state reconciliation pass.
// Non-blocking: if a reconcile is already pending, the request is coalesced.
func (d *Daemon) triggerReconcile() {
	select {
	case d.reconcileNowCh <- struct{}{}:
	default:
	}
}

func shouldRemoveBlackholesOnClusterPrimary(s *rgStateMachine) bool {
	active, _ := s.CurrentDesired()
	return active
}

func (d *Daemon) reconcileRGState() {
	if d.cluster == nil || d.vrrpMgr == nil {
		return
	}

	// Read authoritative VRRP instance states.
	vrrpStates := d.vrrpMgr.InstanceStates()

	// Build per-RG VRRP state map: rgID → { iface → isMaster }.
	// Skip standalone (non-RETH) VRRP instances.
	rgVRRP := make(map[int]map[string]bool)
	for _, ev := range vrrpStates {
		if !isRethVRID(ev.GroupID) {
			continue
		}
		rgID := rgIDFromVRID(ev.GroupID)
		if rgVRRP[rgID] == nil {
			rgVRRP[rgID] = make(map[string]bool)
		}
		rgVRRP[rgID][ev.Interface] = (ev.State == vrrp.StateMaster)
	}

	// Collect all known RG IDs from three sources:
	// 1) existing rgStates (event-driven)
	// 2) cluster-configured groups (may exist before VRRP fires)
	// 3) RETH VRRP instances (may exist before cluster events)
	seen := make(map[int]bool)
	d.rgStatesMu.RLock()
	for rgID := range d.rgStates {
		seen[rgID] = true
	}
	d.rgStatesMu.RUnlock()
	for _, gs := range d.cluster.GroupStates() {
		seen[gs.GroupID] = true
	}
	for rgID := range rgVRRP {
		seen[rgID] = true
	}
	rgIDs := make([]int, 0, len(seen))
	for rgID := range seen {
		rgIDs = append(rgIDs, rgID)
	}

	// Evaluate per-RG readiness for the takeover gate.
	noRethVRRP := d.isNoRethVRRP()

	// Check fabric readiness — only relevant when peer is alive.
	fabricReady := true
	if d.cluster.PeerAlive() {
		d.fabricMu.RLock()
		fp := d.fabricPopulated
		d.fabricMu.RUnlock()
		if !fp {
			d.triggerFabricRefresh()
			fabricReady = false
		}
	}

	if mon := d.cluster.Monitor(); mon != nil {
		for _, rgID := range rgIDs {
			ifReady, ifReasons := mon.RGInterfaceReady(rgID)
			ready, reasons := d.takeoverReadinessForRG(rgID, ifReady, ifReasons, fabricReady, noRethVRRP)
			d.cluster.SetRGReady(rgID, ready, reasons)
		}
	}

	for _, rgID := range rgIDs {
		clusterPri := d.cluster.IsLocalPrimary(rgID)
		vrrp := rgVRRP[rgID] // may be nil if no VRRP instances for this RG
		if vrrp == nil {
			vrrp = make(map[string]bool)
		}

		s := d.getOrCreateRGState(rgID)
		tr := s.Reconcile(clusterPri, vrrp)

		// Desired-vs-applied retry: even if the state machine didn't
		// change this pass, a prior UpdateRGActive failure may have
		// left applied != desired. Retry unconditionally.
		needsApply := tr.Changed || s.NeedsApply()
		if needsApply && d.dp != nil {
			if tr.Changed {
				slog.Info("reconcile: correcting rg_active drift",
					"rg", rgID, "active", tr.Active, "epoch", tr.Epoch)
			} else if s.ShouldLogRetry() {
				// #757: only log retry once per apply streak; subsequent
				// ticks stay silent until MarkApplied() clears the gate.
				slog.Info("reconcile: retrying rg_active apply",
					"rg", rgID, "active", tr.Active)
			}
			if tr.Active {
				// Activation ordering: set rg_active FIRST, then
				// remove blackholes.
				if err := d.dp.HA().SetRGActive(context.Background(), rgID, true); err != nil {
					if s.ShouldLogApplyError(err.Error()) {
						slog.Warn("reconcile: failed to update rg_active",
							"rg", rgID, "active", true, "err", err)
					}
				} else {
					s.MarkApplied(true)
					if noRethVRRP && clusterPri && !s.NeedsApply() {
						d.setLocalFailoverCommitReady(rgID, true)
					}
				}
			} else {
				// Deactivation ordering: blackholes FIRST, then
				// clear rg_active.
				d.injectBlackholeRoutes(rgID)
				d.tryPrepareUserspaceRGDemotion(rgID)
				if err := d.dp.HA().SetRGActive(context.Background(), rgID, false); err != nil {
					if s.ShouldLogApplyError(err.Error()) {
						slog.Warn("reconcile: failed to update rg_active",
							"rg", rgID, "active", false, "err", err)
					}
				} else {
					s.MarkApplied(false)
					d.setLocalFailoverCommitReady(rgID, false)
				}
			}
		}

		// Declarative blackhole route reconciliation: assert the route
		// set that should exist regardless of prior transition results.
		// Active RGs should NOT have blackholes; inactive RGs SHOULD.
		if tr.Active {
			d.removeBlackholeRoutes(rgID)
		} else {
			d.injectBlackholeRoutes(rgID)
		}

		// VRRP posture reconciliation (#86): detect sustained mismatch
		// between cluster state and VRRP state. Only act after 10s+
		// continuous mismatch to avoid fighting transient states (VRRP
		// sync-hold, election timers, hitless restart). Skip entirely
		// during sync-hold when VRRP is intentionally suppressing preempt.
		// Also skip when no-reth-vrrp is active (no RETH VRRP instances).
		//
		// NeedsMaster: only re-send priority update — do NOT call
		// ForceRGMaster here. ForceRGMaster overrides preempt=false,
		// which should only happen from explicit cluster operations
		// (Secondary→Primary in watchClusterEvents). After a reboot
		// the transition is SecondaryHold→Primary, which intentionally
		// skips ForceRGMaster so VRRP respects non-preempt config.
		// The priority update fixes the dropped-event case (#86) while
		// letting VRRP's preempt logic decide whether to transition.
		if d.vrrpMgr != nil && !d.vrrpMgr.InSyncHold() && !noRethVRRP {
			switch s.CheckVRRPPosture(time.Now()) {
			case vrrpPostureNeedsMaster:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=primary but VRRP!=MASTER, re-sending priority",
					"rg", rgID)
				d.vrrpMgr.UpdateRGPriority(rgID, 200)
			case vrrpPostureNeedsResign:
				slog.Warn("reconcile: VRRP posture mismatch — cluster=secondary but VRRP=MASTER, resigning",
					"rg", rgID)
				d.vrrpMgr.ResignRG(rgID)
			}
		}

		// Direct-mode VIP safety net: reconcile desired ownership on every
		// pass from actual cluster state so stale VIPs are removed even if
		// the rg_state machine already thinks the RG is inactive.
		if noRethVRRP {
			d.reconcileDirectVIPOwnership(rgID, "reconcile")
		}

		// RA/DHCP service reconciliation (#93): safety net for dropped
		// VRRP events that should have started or stopped per-RG services.
		// Services (RA/DHCP) only start/stop on actual state change to
		// avoid thrashing restarts every reconcile tick.
		if tr.Changed {
			if tr.Active {
				d.applyRethServicesForRG(rgID)
			} else {
				d.clearRethServicesForRG(rgID)
			}
		}
		// Stable link-local: ensure correct on EVERY reconcile tick.
		// The kernel preserves NODAD addresses across daemon restarts,
		// so stale addresses can exist without a state transition.
		// Direct mode owns this inside reconcileDirectVIPOwnership();
		// VRRP mode keeps the legacy per-tick add/remove behavior here.
		if !noRethVRRP {
			if tr.Active {
				d.addStableRethLinkLocal(rgID)
			} else {
				d.removeStableRethLinkLocal(rgID)
			}
		}

		// Startup goodbye RA: when an RG is inactive on the first
		// reconcile pass (node booted as secondary), send a one-shot
		// goodbye RA (lifetime=0) to clear stale routes from a
		// previous primary run. Each RETH node has a per-node virtual
		// MAC producing a distinct link-local, so hosts see each node
		// as a separate IPv6 router. Without this, hosts ECMP-split
		// traffic to BOTH nodes even though only one is active.
		if !tr.Active && d.ra != nil && !d.startupGoodbyeRA[rgID] {
			if d.startupGoodbyeRA == nil {
				d.startupGoodbyeRA = make(map[int]bool)
			}
			d.startupGoodbyeRA[rgID] = true
			cfg := d.store.ActiveConfig()
			if cfg != nil {
				rgIfaces := rethInterfacesForRG(cfg, rgID)
				rgIfaceSet := make(map[string]bool, len(rgIfaces))
				for _, n := range rgIfaces {
					rgIfaceSet[n] = true
				}
				allRA := d.buildRAConfigs(cfg)
				var rgRA []*config.RAInterfaceConfig
				for _, ra := range allRA {
					if rgIfaceSet[ra.Interface] {
						rgRA = append(rgRA, ra)
					}
				}
				if len(rgRA) > 0 {
					go d.ra.WithdrawOnce(rgRA)
				}
			}
		}
	}
}

// rethInterfacesForRG returns the Linux interface names of RETH interfaces
// belonging to the given redundancy group.
func rethInterfacesForRG(cfg *config.Config, rgID int) []string {
	var names []string
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID && strings.HasPrefix(name, "reth") {
			// Resolve RETH to physical member for Linux-level operations.
			resolved := config.LinuxIfName(cfg.ResolveReth(name))
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					names = append(names, resolved+"."+fmt.Sprintf("%d", unit.VlanID))
				} else {
					names = append(names, resolved)
				}
			}
		}
	}
	return names
}

// injectBlackholeRoutes adds blackhole routes for RETH subnets of the given
// RG. Called on VRRP BACKUP transition — prevents bpf_fib_lookup from routing
// return traffic via the default route (which would escape via WAN). Instead,
// FIB returns BLACKHOLE and the BPF failure handler triggers fabric redirect.
func (d *Daemon) injectBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var routes []netlink.Route
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID || !strings.HasPrefix(name, "reth") {
			continue
		}
		for _, unit := range ifc.Units {
			for _, addr := range unit.Addresses {
				_, ipNet, err := net.ParseCIDR(addr)
				if err != nil {
					slog.Warn("blackhole: failed to parse RETH address",
						"rg", rgID, "iface", name, "addr", addr, "err", err)
					continue
				}
				rt := netlink.Route{
					Dst:      ipNet,
					Type:     unix.RTN_BLACKHOLE,
					Priority: 4242,
				}
				if err := netlink.RouteAdd(&rt); err != nil {
					if errors.Is(err, unix.EEXIST) {
						// Idempotent transition: route already present
						// from a prior BACKUP event. Track it so MASTER
						// cleanup removes it deterministically.
						routes = append(routes, rt)
						slog.Debug("blackhole: route already exists",
							"rg", rgID, "dst", ipNet)
						continue
					}
					slog.Warn("blackhole: failed to add route",
						"rg", rgID, "dst", ipNet, "err", err)
					continue
				}
				routes = append(routes, rt)
				slog.Info("blackhole: injected route for inactive RG",
					"rg", rgID, "dst", ipNet)
			}
		}
	}
	d.blackholeRoutes[rgID] = routes
}

// removeBlackholeRoutes removes blackhole routes previously injected for the
// given RG. Called on VRRP MASTER transition — the connected route returns
// naturally when the VIP is added back.
func (d *Daemon) removeBlackholeRoutes(rgID int) {
	if d.userspaceDataplaneActive() {
		return
	}
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	for _, rt := range d.blackholeRoutes[rgID] {
		if err := netlink.RouteDel(&rt); err != nil {
			if errors.Is(err, unix.ESRCH) {
				// Idempotent transition: route already gone.
				slog.Debug("blackhole: route already removed",
					"rg", rgID, "dst", rt.Dst)
				continue
			}
			slog.Warn("blackhole: failed to remove route",
				"rg", rgID, "dst", rt.Dst, "err", err)
		} else {
			slog.Info("blackhole: removed route for active RG",
				"rg", rgID, "dst", rt.Dst)
		}
	}
	delete(d.blackholeRoutes, rgID)
}

// reconcileBlackholeRoutes removes stale blackhole routes left by a previous
// daemon run. The in-memory blackholeRoutes map is lost on restart, so any
// RTN_BLACKHOLE routes with priority 4242 (our sentinel) survive in the kernel.
// Called once at startup before cluster comms start.
func (d *Daemon) reconcileBlackholeRoutes() {
	d.blackholeMu.Lock()
	defer d.blackholeMu.Unlock()

	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	for _, family := range families {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Type: unix.RTN_BLACKHOLE,
		}, netlink.RT_FILTER_TYPE)
		if err != nil {
			slog.Warn("blackhole: failed to list routes for reconciliation",
				"family", family, "err", err)
			continue
		}
		for _, rt := range routes {
			if rt.Priority != 4242 {
				continue
			}
			if err := netlink.RouteDel(&rt); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("blackhole: failed to remove stale route",
					"dst", rt.Dst, "err", err)
			} else {
				slog.Info("blackhole: removed stale route from previous run",
					"dst", rt.Dst)
			}
		}
	}
}

// applyRethServicesForRG starts RA senders and Kea DHCP server only for
// RETH interfaces belonging to the given RG. Called on VRRP MASTER
// transition — these services must only run on the primary to avoid
// dual-router / dual-DHCP issues.
func (d *Daemon) applyRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	rgIfaces := rethInterfacesForRG(cfg, rgID)
	rgIfaceSet := make(map[string]bool, len(rgIfaces))
	for _, n := range rgIfaces {
		rgIfaceSet[n] = true
	}

	if d.ra != nil {
		allRA := d.buildRAConfigs(cfg)
		var rgRA []*config.RAInterfaceConfig
		for _, ra := range allRA {
			if rgIfaceSet[ra.Interface] {
				rgRA = append(rgRA, ra)
			}
		}
		// Collect RA configs from ALL master RGs (not just this one).
		for otherRG, isMaster := range d.snapshotRethMasterState() {
			if !isMaster || otherRG == rgID {
				continue
			}
			otherIfaces := rethInterfacesForRG(cfg, otherRG)
			otherSet := make(map[string]bool, len(otherIfaces))
			for _, n := range otherIfaces {
				otherSet[n] = true
			}
			for _, ra := range allRA {
				if otherSet[ra.Interface] {
					rgRA = append(rgRA, ra)
				}
			}
		}
		if len(rgRA) > 0 {
			if err := d.ra.Apply(rgRA); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
		if dhcpCfg != nil {
			if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
				slog.Warn("vrrp: failed to apply DHCP server on MASTER", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: DHCP server started (MASTER)", "rg", rgID)
			}
		}
	}
}

// clearRethServicesForRG withdraws RA senders and stops DHCP server only
// for RETH interfaces belonging to the given RG. Called on VRRP BACKUP
// transition. If other RGs are still MASTER, their services remain active.
func (d *Daemon) clearRethServicesForRG(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// Check if any other RG is still master — if so, reapply services for
	// those RGs only; otherwise clear everything.
	anyOtherMaster := false
	for otherRG, isMaster := range d.snapshotRethMasterState() {
		if otherRG != rgID && isMaster {
			anyOtherMaster = true
			break
		}
	}

	if d.ra != nil {
		if anyOtherMaster {
			// Withdraw only this RG's interfaces; reapply others.
			rgIfaces := rethInterfacesForRG(cfg, rgID)
			d.ra.WithdrawInterfaces(rgIfaces)
		} else {
			if err := d.ra.Withdraw(); err != nil {
				slog.Warn("vrrp: failed to withdraw RA on BACKUP", "rg", rgID, "err", err)
			} else {
				slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)", "rg", rgID)
			}
		}
	}
	if d.dhcpServer != nil {
		if anyOtherMaster {
			// Reapply DHCP with only the remaining master RGs' interfaces.
			dhcpCfg := d.filterDHCPConfigForMasterRGs(cfg)
			if dhcpCfg != nil {
				if err := d.dhcpServer.Apply(dhcpCfg); err != nil {
					slog.Warn("vrrp: failed to reapply DHCP after RG BACKUP", "rg", rgID, "err", err)
				}
			} else {
				d.dhcpServer.Clear()
			}
		} else {
			d.dhcpServer.Clear()
			slog.Info("vrrp: DHCP server stopped (BACKUP)", "rg", rgID)
		}
	}
}

// filterDHCPConfigForMasterRGs returns a DHCP config containing only groups
// whose interfaces belong to RGs that are currently MASTER. Returns nil if
// no groups match.
func (d *Daemon) filterDHCPConfigForMasterRGs(cfg *config.Config) *config.DHCPServerConfig {
	// Collect all interfaces belonging to master RGs.
	masterIfaces := make(map[string]bool)
	for rgID, isMaster := range d.snapshotRethMasterState() {
		if !isMaster {
			continue
		}
		for _, n := range rethInterfacesForRG(cfg, rgID) {
			masterIfaces[n] = true
		}
	}

	dhcpCfg := cfg.System.DHCPServer
	resolveDHCPRethInterfaces(&dhcpCfg, cfg)

	filterGroups := func(groups map[string]*config.DHCPServerGroup) map[string]*config.DHCPServerGroup {
		if groups == nil {
			return nil
		}
		result := make(map[string]*config.DHCPServerGroup)
		for name, group := range groups {
			var kept []string
			for _, iface := range group.Interfaces {
				if masterIfaces[iface] {
					kept = append(kept, iface)
				}
			}
			if len(kept) > 0 {
				cp := *group
				cp.Interfaces = kept
				result[name] = &cp
			}
		}
		return result
	}

	var result config.DHCPServerConfig
	if dhcpCfg.DHCPLocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPLocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPLocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		filtered := filterGroups(dhcpCfg.DHCPv6LocalServer.Groups)
		if len(filtered) > 0 {
			result.DHCPv6LocalServer = &config.DHCPLocalServerConfig{Groups: filtered}
		}
	}
	if result.DHCPLocalServer == nil && result.DHCPv6LocalServer == nil {
		return nil
	}
	return &result
}

// applyRethServices starts RA senders and Kea DHCP server. Called on VRRP
// MASTER transition — these services bind to RETH member interfaces
// and must only run on the primary node to avoid dual-RA / dual-DHCP.
// Deprecated: use applyRethServicesForRG for per-RG management.
func (d *Daemon) applyRethServices() {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if d.ra != nil {
		raConfigs := d.buildRAConfigs(cfg)
		if len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("vrrp: failed to apply RA on MASTER", "err", err)
			} else {
				slog.Info("vrrp: RA senders started (MASTER)")
			}
		}
	}
	if d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		dhcpCfg := cfg.System.DHCPServer
		resolveDHCPRethInterfaces(&dhcpCfg, cfg)
		if err := d.dhcpServer.Apply(&dhcpCfg); err != nil {
			slog.Warn("vrrp: failed to apply DHCP server on MASTER", "err", err)
		} else {
			slog.Info("vrrp: DHCP server started (MASTER)")
		}
	}
}

// clearRethServices sends goodbye RAs (lifetime=0) and stops Kea DHCP
// server. Called on VRRP BACKUP transition to prevent the secondary from
// advertising RAs or serving DHCP leases. The goodbye RA tells hosts to
// immediately remove this router as a default gateway.
// Deprecated: use clearRethServicesForRG for per-RG management.
func (d *Daemon) clearRethServices() {
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("vrrp: failed to withdraw RA on BACKUP", "err", err)
		} else {
			slog.Info("vrrp: RA withdrawn (BACKUP, goodbye RA sent)")
		}
	}
	if d.dhcpServer != nil {
		d.dhcpServer.Clear()
		slog.Info("vrrp: DHCP server stopped (BACKUP)")
	}
}

// warmNeighborCache iterates synced sessions and sends ARP requests /
// ICMPv6 Neighbor Solicitations for unique destination IPs. This
// pre-populates the kernel neighbor cache so that bpf_fib_lookup
// returns SUCCESS (not NO_NEIGH) for the first packet after failover.
func (d *Daemon) warmNeighborCache() {
	if d.dp == nil {
		return
	}

	seen := make(map[[4]byte]bool)
	seenV6 := make(map[[16]byte]bool)

	// Iterate IPv4 sessions: collect unique dst IPs (forward entries
	// need ARP for the next-hop toward the destination) and unique src IPs
	// (return entries need ARP for the on-link client).
	_ = d.dp.Sessions().ForEachV4(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seen[key.DstIP] {
			seen[key.DstIP] = true
		}
		if !seen[key.SrcIP] {
			seen[key.SrcIP] = true
		}
		return true
	})

	// Iterate IPv6 sessions.
	_ = d.dp.Sessions().ForEachV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if !seenV6[key.DstIP] {
			seenV6[key.DstIP] = true
		}
		if !seenV6[key.SrcIP] {
			seenV6[key.SrcIP] = true
		}
		return true
	})

	// Resolve IPv4 neighbors by sending a UDP packet to trigger kernel ARP.
	// UDP connect() alone does NOT trigger ARP — only the route lookup is
	// performed. We must send at least one byte so the kernel actually
	// calls neigh_resolve_output() → arp_solicit().
	count := 0
	for ip4 := range seen {
		addr := netip.AddrFrom4(ip4)
		if !addr.IsGlobalUnicast() || addr.IsPrivate() && addr.IsLoopback() {
			continue
		}
		conn, err := net.DialTimeout("udp4", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers ARP resolution
			conn.Close()
			count++
		}
	}

	// Resolve IPv6 neighbors.
	countV6 := 0
	for ip6 := range seenV6 {
		addr := netip.AddrFrom16(ip6)
		if !addr.IsGlobalUnicast() {
			continue
		}
		conn, err := net.DialTimeout("udp6", netip.AddrPortFrom(addr, 1).String(), 50*time.Millisecond)
		if err == nil {
			conn.Write([]byte{0}) // triggers NDP resolution
			conn.Close()
			countV6++
		}
	}

	if count > 0 || countV6 > 0 {
		slog.Info("cluster: neighbor cache warmup complete",
			"ipv4_hosts", count, "ipv6_hosts", countV6)
		// Brief pause to allow ARP/NDP responses before traffic arrives.
		time.Sleep(200 * time.Millisecond)
	}
}

// clusterConfig returns the current cluster config or nil.
func (d *Daemon) clusterConfig() *config.ClusterConfig {
	if d.store == nil {
		return nil
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	return cfg.Chassis.Cluster
}

// syncIPsecSAPeriodic runs on the primary node, periodically syncing active IPsec
// connection names to the secondary via the session sync channel.
func (d *Daemon) syncIPsecSAPeriodic(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
				continue
			}
			cc := d.clusterConfig()
			if cc == nil || !cc.IPsecSASync {
				continue
			}
			names, err := d.ipsec.ActiveConnectionNames()
			if err != nil {
				slog.Debug("cluster: failed to get IPsec connection names", "err", err)
				continue
			}
			if len(names) > 0 && d.sessionSync != nil {
				d.sessionSync.QueueIPsecSA(names)
			}
		}
	}
}

// reinitiateIPsecSAs re-initiates all IPsec connections that were synced from the
// previous primary. Called when this node becomes primary after failover.
func (d *Daemon) reinitiateIPsecSAs() {
	names := d.sessionSync.PeerIPsecSAs()
	if len(names) == 0 {
		return
	}
	slog.Info("cluster: re-initiating IPsec SAs after failover", "count", len(names))
	for _, name := range names {
		if err := d.ipsec.InitiateConnection(name); err != nil {
			slog.Warn("cluster: failed to initiate IPsec SA", "name", name, "err", err)
		} else {
			slog.Info("cluster: IPsec SA initiated", "name", name)
		}
	}
}

// resolveDHCPRethInterfaces translates RETH interface names in DHCP server
// groups to their physical member Linux names (Kea needs real device names).
func resolveDHCPRethInterfaces(dhcpCfg *config.DHCPServerConfig, cfg *config.Config) {
	resolve := func(groups map[string]*config.DHCPServerGroup) {
		for _, group := range groups {
			for i, iface := range group.Interfaces {
				group.Interfaces[i] = config.LinuxIfName(cfg.ResolveReth(iface))
			}
		}
	}
	if dhcpCfg.DHCPLocalServer != nil {
		resolve(dhcpCfg.DHCPLocalServer.Groups)
	}
	if dhcpCfg.DHCPv6LocalServer != nil {
		resolve(dhcpCfg.DHCPv6LocalServer.Groups)
	}
}
