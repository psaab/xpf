package userspace

import (
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
)

// neighborIndexKey is the (ifindex, ip-string) key for the
// O(1) neighbor lookup index used by the daemon's listener hot
// path. ip-string is used (not net.IP) so map equality is well-
// defined for both v4 and v6 representations.
type neighborIndexKey struct {
	ifindex int
	ip      string
}

// filterPublishableNeighbors returns only the entries
// userspace-dp will accept (per neighborSnapshotPublishable).
func filterPublishableNeighbors(neighbors []NeighborSnapshot) []NeighborSnapshot {
	out := make([]NeighborSnapshot, 0, len(neighbors))
	for _, n := range neighbors {
		if neighborSnapshotPublishable(n) {
			out = append(out, n)
		}
	}
	return out
}

// seedNeighborReplaceGenerationLocked advances the manager's replace counter
// to the helper's applied-generation fence without ever moving it backwards.
// Caller must hold m.mu.
func (m *Manager) seedNeighborReplaceGenerationLocked(appliedGeneration uint64) {
	if appliedGeneration > m.neighborReplaceGen {
		m.neighborReplaceGen = appliedGeneration
	}
}

// rebuildNeighborIndex updates m.neighborIndex from the current
// m.lastSnapshot.Neighbors slice. Caller MUST hold m.mu. Called
// after every assignment to lastSnapshot.Neighbors.
//
// Codex code-review v2 #1: index ONLY publishable entries.
// Indexing raw entries causes a bug: a raw failed→reachable
// transition on the same MAC would return existing.MAC == new.MAC
// from LookupSnapshotNeighbor → shouldTriggerRegen returns false
// → snapshot stays out of date until 60s safety tick. By indexing
// only publishable entries, an unpublishable→publishable
// transition presents as "no existing entry" → trigger fires.
func (m *Manager) rebuildNeighborIndex() {
	if m.lastSnapshot == nil {
		m.neighborIndex = nil
		return
	}
	idx := make(map[neighborIndexKey]*NeighborSnapshot,
		len(m.lastSnapshot.Neighbors))
	for i := range m.lastSnapshot.Neighbors {
		n := &m.lastSnapshot.Neighbors[i]
		if !neighborSnapshotPublishable(*n) {
			continue
		}
		idx[neighborIndexKey{n.Ifindex, n.IP}] = n
	}
	m.neighborIndex = idx
}

// RegenerateNeighborSnapshot rebuilds the in-memory neighbor
// snapshot from current kernel ARP/NDP state and publishes any
// forwarding-relevant changes to userspace-dp.
//
// #1197: this is the event-driven entry point used by the
// daemon's RTM_NEWNEIGH/DELNEIGH listener (and the 60s safety
// reconciliation tick) to keep the userspace-dp neighbor table
// in sync with the kernel without depending on the buggy
// preinstall mechanism.
//
// Forwarding-effective diff (key, MAC, publishable-bit) decides
// whether to publish; raw NUD state (REACHABLE↔STALE) is ignored
// to avoid republish churn.
func (m *Manager) RegenerateNeighborSnapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	if m.proc == nil || m.proc.Process == nil {
		return
	}
	// #1197 v4 (Codex code-review v3 #1): refresh monitored
	// ifindex cache unconditionally — a regen call may be
	// triggered by the safety tick precisely because a link
	// changed, and the listener filter must reflect that even
	// if neighbor entries didn't diff.
	m.rebuildMonitoredIfindexes()

	newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
	if neighborsEqualForwarding(m.lastSnapshot.Neighbors, newNeighbors) {
		return
	}
	publishable := filterPublishableNeighbors(newNeighbors)
	// #6034: stamp a fresh monotonic replace generation so the helper can
	// fence a stale/reordered replace and ACK the applied generation.
	m.neighborReplaceGen++
	gen := m.neighborReplaceGen
	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{
		Type:               "update_neighbors",
		Neighbors:          publishable,
		NeighborReplace:    true,
		NeighborGeneration: gen,
	}, &status); err != nil {
		slog.Warn("userspace: failed to publish neighbor regeneration", "err", err)
		return
	}
	// #6034: retain retry debt if the helper did not acknowledge applying
	// this replace generation. A helper that supports the ACK echoes the
	// applied generation; a value below `gen` means it fenced the replace
	// as stale, so we leave the cached neighbor view untouched and the next
	// regeneration re-diffs and retries with a strictly higher generation.
	// An ACK of 0 means an older helper without ACK support — assume applied
	// (preserves pre-#6034 behavior).
	if status.ManagerNeighborGeneration != 0 && status.ManagerNeighborGeneration < gen {
		slog.Warn("userspace: neighbor regeneration not acknowledged; retaining retry debt",
			"sent_generation", gen,
			"applied_generation", status.ManagerNeighborGeneration)
		return
	}
	m.lastSnapshot.Neighbors = newNeighbors
	m.rebuildNeighborIndex() // #1197 (after publish success)
	m.generation++
	m.lastSnapshot.Generation = m.generation
	// Copilot review: advance publishedSnapshot + refresh
	// lastSnapshotHash. Otherwise the status loop sees the
	// bumped generation as unpublished and may force a redundant
	// apply_snapshot, AND any churn in filtered-out rows could
	// leak through hash-dedup.
	m.publishedSnapshot = m.lastSnapshot.Generation
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
}

// LookupSnapshotNeighbor returns a copy of the snapshot's
// current entry for (ifindex, ip), or nil if not present. The
// returned snapshot is a value copy — safe to read after the
// lock is released, and avoids the (currently no-op) mutation
// hazard of returning an internal pointer.
//
// Codex code-review v2 #4: previous version returned a defensive
// pointer via heap copy. Caller (shouldTriggerRegen) only reads
// the MAC immediately while still under m.mu, so a pointer is
// safe. But the API surface is cleaner as a value (caller can
// hold it across other lock-acquiring calls without aliasing
// concerns), so we keep the value-copy semantics — just skip
// the heap-allocated *NeighborSnapshot wrapping.
//
// Index covers ONLY publishable entries (#1 v2 fix), so a hit
// here means userspace-dp has been told about this entry.
func (m *Manager) LookupSnapshotNeighbor(ifindex int, ip net.IP) *NeighborSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.neighborIndex == nil {
		return nil
	}
	entry, ok := m.neighborIndex[neighborIndexKey{ifindex, ip.String()}]
	if !ok {
		return nil
	}
	out := *entry
	return &out
}

// IsMonitoredIfindex returns true if the given link index
// belongs to a configured interface that buildNeighborSnapshots
// would iterate. O(1) hash-map lookup under m.mu.
//
// Codex code-review v2 #2: previous version returned a copy of
// the whole map, which made the listener hot path O(configured-
// interfaces) plus heap churn per event. This direct lookup
// avoids both.
func (m *Manager) IsMonitoredIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.monitoredIfindexes == nil {
		return false
	}
	_, ok := m.monitoredIfindexes[ifindex]
	return ok
}

// rebuildMonitoredIfindexes updates m.monitoredIfindexes from
// the active config. Caller MUST hold m.mu.
//
// Codex code-review v2 #3: previous version was called only on
// full snapshot assignment. Neighbor-only updates (BumpFIBGeneration,
// RegenerateNeighborSnapshot) didn't refresh the cache, so a
// configured link recreated under a new ifindex could have its
// events dropped. Now called from every neighbor-related update
// path that may reflect a new ifindex.
func (m *Manager) rebuildMonitoredIfindexes() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		m.monitoredIfindexes = nil
		return
	}
	m.monitoredIfindexes = MonitoredInterfaceLinkIndexes(m.lastSnapshot.Config)
}

// ForEachSnapshotNeighbor invokes fn for every PUBLISHABLE
// neighbor entry in the current snapshot (i.e., entries
// userspace-dp accepted into its forwarding table).
//
// #1197 (Copilot review): the existing SnapshotNeighbors() walks
// raw lastSnapshot.Neighbors which can include filtered-out
// entries (FAILED/INCOMPLETE/none). For force-probe target
// collection we want only the entries the dataplane is actually
// using, so we walk neighborIndex (publishable-only).
//
// #5250 (A6-b2 F1): fn is invoked AFTER m.mu is released. Calling a
// caller-supplied callback while holding the manager lock made every
// re-entrant Manager call from fn a self-deadlock, and held mu across
// arbitrary user work (force-probe emission does netlink/control-socket I/O)
// where the control socket is already the contended resource. The walk now
// snapshots (ifindex, ip) pairs under the lock and calls fn on that snapshot
// with the lock dropped; a concurrent snapshot refresh may therefore land
// between the copy and the callback, which is the same staleness every other
// caller of this best-effort probe-target view already tolerates.
func (m *Manager) ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP)) {
	type snapshotNeighbor struct {
		ifindex int
		ip      net.IP
	}
	m.mu.Lock()
	targets := make([]snapshotNeighbor, 0, len(m.neighborIndex))
	for k, n := range m.neighborIndex {
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		targets = append(targets, snapshotNeighbor{ifindex: k.ifindex, ip: ip})
	}
	m.mu.Unlock()
	for _, t := range targets {
		fn(t.ifindex, t.ip)
	}
}

// SnapshotHasIfindex returns true if the current snapshot
// contains any neighbor entry on the given ifindex. Used by the
// daemon's listener filter as a fallback for runtime ifindex
// drift. O(N) scan over the neighborIndex but the listener
// already pays O(1) for the LookupSnapshotNeighbor; this fallback
// only fires when the config-derived monitored set doesn't
// contain the ifindex (rare, e.g., link disappeared).
func (m *Manager) SnapshotHasIfindex(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.neighborIndex {
		if k.ifindex == ifindex {
			return true
		}
	}
	return false
}

// SnapshotNeighbors returns the neighbor entries from the last published
// snapshot. Used by the daemon to pre-install kernel ARP entries on RG
// activation so failback doesn't drop packets during ARP resolution.
func (m *Manager) SnapshotNeighbors() []struct {
	Ifindex int
	IP      net.IP
	MAC     net.HardwareAddr
	Family  int
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot == nil {
		return nil
	}
	var result []struct {
		Ifindex int
		IP      net.IP
		MAC     net.HardwareAddr
		Family  int
	}
	for _, n := range m.lastSnapshot.Neighbors {
		if n.Ifindex <= 0 || n.MAC == "" || n.IP == "" {
			continue
		}
		mac, err := net.ParseMAC(n.MAC)
		if err != nil {
			continue
		}
		ip := net.ParseIP(n.IP)
		if ip == nil {
			continue
		}
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		result = append(result, struct {
			Ifindex int
			IP      net.IP
			MAC     net.HardwareAddr
			Family  int
		}{
			Ifindex: n.Ifindex,
			IP:      ip,
			MAC:     mac,
			Family:  family,
		})
	}
	return result
}
