package userspace

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

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
	liveXfrm := sampleLiveXfrmNetdevs()
	next.Interfaces = buildInterfaceSnapshotsFrom(cfg, liveXfrm)
	// First drop rows already absent at this sample. requestApplySnapshotLocked
	// repeats this immediately before hashing/sending to catch churn during the
	// rest of the rebuild.
	revalidateSnapshotIfindexes(&next)
	var err error
	next.Routes, next.LearnedRouteImportCapped, err = buildRouteSnapshots(cfg, next.Interfaces, m.routeOverlay)
	if err != nil {
		return false, fmt.Errorf("build interface-link refresh routes: %w", err)
	}
	next.Fabrics = buildFabricSnapshotsFrom(cfg, liveXfrm)
	next.TunnelEndpoints = buildTunnelEndpointSnapshots(cfg, next.Interfaces)
	next.MirrorConfigs, next.MirrorExclusions = buildMirrorConfigSnapshots(cfg, next.Interfaces)
	m.refreshCaptureAuthorityLocked(&next)
	resampled := m.resampleUnresolvedSectionsLocked(&next)

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
	generation := m.generation
	if generation < current.Generation {
		generation = current.Generation
	}
	if generation == math.MaxUint64 {
		return false, fmt.Errorf("userspace: snapshot generation exhausted during interface-link refresh")
	}
	next.Generation = generation + 1
	next.FIBGeneration = m.readFIBGeneration()
	next.GeneratedAt = time.Now().UTC()
	if err := m.disarmBeforeUnsupportedPublishLocked(&next); err != nil {
		return false, err
	}

	publishSnap := next
	publishSnap.Neighbors = filterPublishableNeighbors(next.Neighbors)
	var status ProcessStatus
	if err := m.requestApplySnapshotLocked(&publishSnap, &status); err != nil {
		return false, fmt.Errorf("publish interface-link refresh: %w", err)
	}
	// requestApplySnapshotLocked may have refreshed or dropped rows at the
	// send boundary. Retain exactly those rows rather than resurrecting the
	// pre-boundary copy on the next partial publish.
	next.Interfaces = publishSnap.Interfaces
	m.commitPolicySchedulerActiveStateFromSnapshotLocked(&next)
	m.logWgEndpointSetTransitionLocked(&publishSnap, "interface-link")
	m.adoptPublishedGenerationLocked(&next, publishSnap.Generation)
	m.lastSnapshot = &next
	m.rebuildNeighborIndex()
	m.rebuildMonitoredIfindexes()
	m.publishedSnapshot = next.Generation
	m.pendingFullSnapshotMetadata = false
	m.publishedPlanKey = snapshotBindingPlanKey(&next)
	m.markAppliedSnapshotLocked()
	if h, ok := snapshotContentHash(&next); ok {
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
