package userspace

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/config"
)

// InterfaceLinkNameRelevant reports whether linuxName backs an interface row
// in the retained desired config. The config, rather than lastSnapshot's
// published rows, is authoritative: apply-time revalidation may have dropped a
// deleted row, and a later recreation must be able to restore it.
func (m *Manager) InterfaceLinkNameRelevant(linuxName string) bool {
	if m == nil || linuxName == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSnapshot != nil && configuredInterfaceLinkName(m.lastSnapshot.Config, linuxName)
}

// InterfaceLinkRefreshTriggerName returns one configured netdev name whose
// refresh rebuilds every interface row. It is used after RTNL resubscription
// to repair notifications lost while the socket was down.
func (m *Manager) InterfaceLinkRefreshTriggerName() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil {
		return ""
	}
	cfg := m.lastSnapshot.Config
	if cfg == nil {
		return ""
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if iface := cfg.Interfaces.Interfaces[name]; iface != nil {
			if linuxName := snapshotLinuxName(cfg, name, iface, nil); linuxName != "" {
				return linuxName
			}
		}
	}
	tunnelNames := make([]string, 0)
	for ref := range authoredZoneRefs(cfg) {
		if linuxName, ok := cfg.SecureTunnelNetdevForRef(ref); ok && linuxName != "" {
			tunnelNames = append(tunnelNames, linuxName)
		}
	}
	sort.Strings(tunnelNames)
	if len(tunnelNames) > 0 {
		return tunnelNames[0]
	}
	return ""
}

// RefreshInterfaceRowsForLink rebuilds link-derived snapshot sections from cfg
// and publishes them only when the rebuilt snapshot differs. The daemon holds
// applySem while calling this method; m.mu additionally fences against every
// other manager publisher from sampling the current retained snapshot through
// committing the new generation.
func (m *Manager) RefreshInterfaceRowsForLink(cfg *config.Config, linuxName string) (bool, error) {
	if m == nil || linuxName == "" {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.lastSnapshot
	if current == nil || current.Config == nil || !configuredInterfaceLinkName(current.Config, linuxName) {
		return false, nil
	}
	// The caller samples ActiveConfig only after acquiring applySem. Refuse a
	// stale or failed config apply rather than making a hybrid snapshot from a
	// config the helper has not accepted.
	if cfg == nil || cfg != current.Config {
		return false, nil
	}
	if m.proc == nil || m.proc.Process == nil {
		return false, fmt.Errorf("userspace: helper unavailable during interface link refresh")
	}

	wasDebt := m.snapshotRetryDebtLocked()
	next := *current
	if !m.pendingFullSnapshotMetadata {
		stripSingleUseCommitMetadata(&next)
	}
	next.Config = cfg

	// Always rebuild from the desired config. Cloning current.Interfaces would
	// make a row removed by #11086 unrecoverable when its netdev is recreated.
	// Capture the fresh xfrm dump status exactly as the full build does
	// (builder.go): retaining the previous snapshot's stale value would grant
	// or withhold the NIC-tuning allowlist on old evidence (#14133).
	liveXfrm, xfrmDumpFailed := sampleLiveXfrmNetdevs()
	next.xfrmDumpFailed = xfrmDumpFailed
	next.Interfaces = buildInterfaceSnapshotsFrom(cfg, liveXfrm)
	// Rows are freshly built here, so revalidate their owned backing once before
	// deriving routes and other interface-dependent sections. The prepared send
	// below must not take a second kernel sample.
	if refreshed, dropped := revalidateSnapshotIfindexesInPlace(&next); refreshed+dropped > 0 {
		slog.Info("userspace: snapshot interface rows revalidated at apply",
			"refreshed", refreshed, "dropped", dropped)
	}
	var err error
	next.Routes, next.LearnedRouteImportCapped, err = buildRouteSnapshotsWithRGPrimary(cfg, next.Interfaces, m.routeOverlay, m.rgPrimaryProvider)
	if err != nil {
		return false, fmt.Errorf("build interface-link refresh routes: %w", err)
	}
	next.Interfaces = markConnectedRGPeerOwned(cfg, next.Interfaces, m.rgPrimaryProvider)
	next.Fabrics = buildFabricSnapshotsFrom(cfg, liveXfrm)
	next.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, next.Interfaces)
	next.MirrorConfigs, next.MirrorExclusions = buildMirrorConfigSnapshots(cfg, next.Interfaces)
	// #14133: re-establish the full-build zone-isolation invariant on the
	// freshly rebuilt rows. builder.go runs quarantineCollidingZones after
	// every full build; without it a recreated interface in a quarantined
	// (StableZoneID-colliding / poisoned / reserved) zone would be published
	// zoned, resurrecting the merged-zone hazard and dangling policy/zone
	// references. quarantineCollidingZones is idempotent on an already
	// reduced snapshot (survivor policies/zones stay reduced), so applying
	// it here mirrors the full build. Carry the diagnostic forward and
	// recompute ZoneSetValidated and the summary counts exactly as builder.go.
	// #14964: preserve both full-build quarantines on this snapshot rebuild.
	// The alias must be detached before mutating NAT quarantine, because a
	// no-hash refresh must not alter the retained snapshot.
	next.SourceNAT = append([]SourceNATRuleSnapshot(nil), next.SourceNAT...)
	// Deriving validated state from locally recorded collisions alone is
	// wrong when next copies an already-reduced snapshot but the current
	// config's runtime quarantine cannot reproduce the prior record: the
	// re-run returns no collisions and would flip ZoneSetValidated to true.
	// When the rebuilt zone set is exactly the prior published set, keep the
	// prior quarantine record and validated state. A changed zone set is
	// evaluated by quarantine itself and then recomputed normally.
	publishedZonesBefore := append([]ZoneSnapshot(nil), current.Zones...)
	next.zoneIDCollisions = quarantineCollidingZones(&next)
	sameZones := len(next.Zones) == len(publishedZonesBefore)
	if sameZones {
		for i := range next.Zones {
			if next.Zones[i].Name != publishedZonesBefore[i].Name || next.Zones[i].ID != publishedZonesBefore[i].ID {
				sameZones = false
				break
			}
		}
	}
	if sameZones {
		next.ZoneSetValidated = current.ZoneSetValidated && len(next.Zones) > 0
		if len(current.zoneIDCollisions) > 0 {
			next.zoneIDCollisions = current.zoneIDCollisions
		}
	} else {
		next.ZoneSetValidated = len(next.Zones) > 0 && len(next.zoneIDCollisions) == 0
	}
	if len(next.zoneIDCollisions) > 0 {
		next.Summary.ZoneCount = len(next.Zones)
		next.Summary.PolicyCount = len(next.Policies)
	}
	reportInterfaceSNATPoolOverlaps(&next)
	// Policy refusal reasons must name the exact post-quarantine policy/zone
	// sets this refresh publishes (builder.go recomputes them the same way);
	// otherwise a refresh that newly quarantines a zone keeps stale reasons
	// and one that clears it keeps phantom refusals.
	m.recordPolicyContentRejectionLocked(next.Capabilities.PolicyContentRejected)
	m.recordZoneIDCollisionsLocked(next.zoneIDCollisions)
	generation := m.generation
	if generation < current.Generation {
		generation = current.Generation
	}
	if generation < math.MaxUint64 {
		next.Generation = generation + 1
	} else {
		next.Generation = generation
	}
	next.FIBGeneration = m.readFIBGeneration()
	resampled := m.resampleUnresolvedSectionsLocked(&next)
	m.refreshCaptureAuthorityLocked(&next)
	// #15042: run the attach reconcile BEFORE (independent of) the hash
	// dedup below. A prior non-Compile republish may have already adopted
	// this recreated ifindex into lastSnapshot+hash without attaching
	// (the pre-#15042 shared-send bug, or any attach that failed then);
	// deduping first would return (false, nil) and leave the interface
	// unshimmed until the next full Compile. The reconcile is a no-op
	// for tracked ifindexes, so an unchanged refresh issues no attach.
	m.reconcileInterfaceAttachmentsForRefreshLocked(&next)
	if h, ok := snapshotContentHash(&next); ok && h == m.lastSnapshotHash &&
		!m.applySnapshotOutcomeUnknown && m.partialOutcomeUnknown == 0 && resampled == 0 {
		return false, nil
	}
	if err := m.ensureRequiredSnapshotProtocolLocked(&next); err != nil {
		if disarmErr := m.disarmSnapshotProtocolFailureLocked(err); disarmErr != nil {
			slog.Warn("userspace: failed to disarm helper after refusing interface-link refresh",
				"protocol_err", err, "err", disarmErr)
		}
		return false, fmt.Errorf("refusing interface-link refresh to incompatible helper: %w", err)
	}
	if generation == math.MaxUint64 {
		return false, fmt.Errorf("userspace: snapshot generation exhausted during interface-link refresh")
	}
	next.GeneratedAt = time.Now().UTC()
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}

	// #14133/#15042: the attach reconcile already ran above, before the
	// hash dedup, so it covers both the deduped and the publishing path;
	// it is a no-op for already-tracked ifindexes.
	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	if err := m.requestApplySnapshotPreparedLocked(&publishSnap, &status); err != nil {
		return false, fmt.Errorf("publish interface-link refresh: %w", err)
	}
	// next already owns the interface rows sampled before this publish.
	m.commitPolicySchedulerActiveStateFromSnapshotLocked(&next)
	m.logWgEndpointSetTransitionLocked(&publishSnap, "interface-link")
	m.adoptPublishedGenerationLocked(&next, publishSnap.Generation)
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.pendingFullSnapshotMetadata = false
	m.publishedPlanKey = snapshotBindingPlanKey(&publishSnap)
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&publishSnap); ok {
		m.lastSnapshotHash = h
	}
	m.resolvePartialOutcomesLocked(resampled)
	m.armPendingHAStateReplayLocked(wasDebt)
	if err := m.applyHelperStatusLocked(&status); err != nil {
		slog.Warn("userspace: failed to sync helper status after interface-link refresh", "err", err)
	}
	slog.Info("userspace: interface rows refreshed after link change", "generation", next.Generation,
		"linux_name", linuxName)
	return true, nil
}

// reconcileInterfaceAttachmentsForRefreshLocked brings the kernel XDP
// attachment set in line with next before next is published (#14133).
// Caller holds m.mu.
//
// Attach half: every ingress ifindex in next that is not already tracked is
// attached now. A recreated link has a new ifindex, so it lands here; an
// unchanged link keeps its existing tracked link. The forceGeneric
// classification mirrors Compile's attachUserspaceShimXDP: a tunnel netdev
// (SecureTunnel row) or a VLAN child (ParentIfindex > 0) goes generic,
// everything else tries native first with a generic fallback. An attach
// failure is logged and left for the next refresh/full apply to retry — it
// must not fail this publish, because the helper's snapshot update is still
// correct and the unshimmed interface is fail-closed (no program,
// fence-dropped transit), never fail-open.
//
// Detach half is intentionally NOT done here: detaching an obsolete ifindex
// before the helper accepts next would repeat the #5485 bypass if the
// publish then failed and the retained snapshot still adjudicated it. The
// obsolete attachment is reaped by the next full Compile's post-acceptance
// syncInterfaceAttachments; the lingering shim is the bounded mirror
// transient documented in applyCompiledSnapshot (#10642).
func (m *Manager) reconcileInterfaceAttachmentsForRefreshLocked(next *ConfigSnapshot) {
	if m == nil || next == nil {
		return
	}
	if m.bpfShim == nil && m.attachInterfaceXDPHook == nil {
		return
	}
	var tracked map[int]link.Link
	if m.bpfShim != nil {
		tracked = m.bpfShim.XDPLinks()
	}
	for _, ifindex := range buildUserspaceIngressIfindexes(next) {
		if ifindex == 0 {
			continue
		}
		if _, ok := tracked[int(ifindex)]; ok {
			continue
		}
		row := interfaceRowForIfindex(next, ifindex)
		forceGeneric := row != nil && (row.SecureTunnel || row.ParentIfindex > 0 || row.Tunnel)
		var attach func(int, bool) error
		if m.bpfShim != nil {
			attach = m.bpfShim.AttachXDP
		}
		if m.attachInterfaceXDPHook != nil {
			attach = m.attachInterfaceXDPHook
		}
		if attach == nil {
			continue
		}
		if err := attach(int(ifindex), forceGeneric); err != nil {
			if attachErrIsAlreadyAttached(err) {
				continue
			}
			if !forceGeneric {
				if gerr := attach(int(ifindex), true); gerr == nil || attachErrIsAlreadyAttached(gerr) {
					continue
				} else {
					err = gerr
				}
			}
			slog.Warn("userspace: failed to attach XDP shim during interface-link refresh; interface remains fail-closed until the next apply",
				"ifindex", ifindex, "err", err, "issue", "#14133")
		}
	}
}

// attachErrIsAlreadyAttached reports whether an AttachXDP error is the
// benign "already attached" short-circuit (dataplane.Manager.AttachXDP).
func attachErrIsAlreadyAttached(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already attached")
}

// interfaceRowForIfindex returns the snapshot row that contributes ifindex
// to the ingress set (its own ifindex or, for a parent contribution, the row
// whose ParentIfindex matches), or nil when no row matches.
func interfaceRowForIfindex(snap *ConfigSnapshot, ifindex uint32) *InterfaceSnapshot {
	if snap == nil {
		return nil
	}
	for i := range snap.Interfaces {
		if uint32(snap.Interfaces[i].Ifindex) == ifindex || uint32(snap.Interfaces[i].ParentIfindex) == ifindex {
			return &snap.Interfaces[i]
		}
	}
	return nil
}

func configuredInterfaceLinkName(cfg *config.Config, linuxName string) bool {
	if cfg == nil || linuxName == "" {
		return false
	}
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		if snapshotLinuxName(cfg, name, iface, nil) == linuxName {
			return true
		}
		for _, unit := range iface.Units {
			if unit != nil && snapshotLinuxName(cfg, name, iface, unit) == linuxName {
				return true
			}
		}
	}
	for ref := range authoredZoneRefs(cfg) {
		if name, ok := cfg.SecureTunnelNetdevForRef(ref); ok && name == linuxName {
			return true
		}
	}
	return false
}
