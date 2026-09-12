package dataplane

import (
	"maps"

	"github.com/cilium/ebpf/link"
)

// Guarded access to the Manager's link-membership maps (#6740).
//
// xdpLinks / tcLinks / vlanSubInterfaces are all protected by Manager.mu. They
// live behind these accessors rather than being touched directly because the
// 1 Hz userspace status path ranged them while CompileUserspaceShim / AttachXDP
// / DetachXDP mutated them, and a concurrent Go map read+write is a fatal
// runtime.throw rather than a torn value.
//
// Two rules hold throughout:
//
//   - nothing hands out a live map. XDPLinks/TCLinks return SNAPSHOTS, because
//     returning the map by reference puts the caller's range loop outside any
//     lock the accessor could take — which is precisely how the race survived
//     the #2114 A3 registry rule.
//   - no lock spans a syscall. Callers that must issue netlink/BPF work take a
//     snapshot (xdpSwapTargets), or read an entry, act unlocked, then write
//     (DetachXDP) — the lock is never held across link.Update / link.Close.
//
// Split out of loader.go by #6740, which pushed that file past the 1500 LOC
// [WATCH] floor. The move is verbatim: these are the same methods, in the same
// order, with no behaviour change.

// XDPLinks returns a SNAPSHOT of the attached XDP links (#6740).
//
// It used to return the live map by reference, which put every caller's range
// loop outside any lock this accessor could take — the 1 Hz userspace status
// path ranged it while CompileUserspaceShim/AttachXDP/DetachXDP mutated it, and
// a concurrent Go map read+write is a fatal runtime.throw. A copy is the only
// shape that makes the caller's loop safe without exporting the lock.
//
// The copy also makes the detach-while-ranging loop in
// pkg/dataplane/userspace (manager_compile.go, which calls DetachXDP for each
// non-data ifindex it iterates) operate on a stable set rather than the map it
// is mutating.
func (m *Manager) XDPLinks() map[int]link.Link {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.xdpLinks)
}

// TCLinks returns a SNAPSHOT of the attached TC links, for the same reason as
// XDPLinks — the sibling map has the identical exposure through the identical
// accessor, and fixing one while leaving the other is a half-fix.
func (m *Manager) TCLinks() map[int]link.Link {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.tcLinks)
}

// xdpSwapTarget is one interface the entry-program swap must update.
type xdpSwapTarget struct {
	ifindex int
	link    link.Link
}

// xdpSwapTargets snapshots the non-VLAN XDP links under a single m.mu hold, so
// the link set and the VLAN-skip decision come from the SAME instant. The
// caller runs its BPF updates on the returned slice with the lock released.
func (m *Manager) xdpSwapTargets() []xdpSwapTarget {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]xdpSwapTarget, 0, len(m.xdpLinks))
	for ifindex, l := range m.xdpLinks {
		if m.vlanSubInterfaces[ifindex] {
			continue
		}
		out = append(out, xdpSwapTarget{ifindex: ifindex, link: l})
	}
	return out
}

// XDPEntryPrograms returns ifindex -> attached XDP entry-program name for every
// non-VLAN attached interface, read under ONE m.mu hold (#6740).
//
// This is what the 1 Hz userspace status path consumes. It exists as a single
// accessor rather than three calls because the status path previously ranged
// the live xdpLinks map, indexed the exported VlanSubInterfaces map and read
// xdpEntryProg separately: three unsynchronised reads of state that mutates
// under it. One lock gives a consistent view and removes the cross-package
// reach into the manager's maps entirely.
//
// VLAN sub-interfaces are excluded: they are skipped during userspace-shim
// swaps and may retain the parent's program, so reporting the entry program for
// them would be a lie.
func (m *Manager) XDPEntryPrograms() map[int]string {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("XDPEntryPrograms")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.xdpLinks) == 0 {
		return nil
	}
	out := make(map[int]string, len(m.xdpLinks))
	for ifindex := range m.xdpLinks {
		if m.vlanSubInterfaces[ifindex] {
			continue
		}
		out[ifindex] = m.xdpEntryProg
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// The per-entry helpers below exist so no call site touches the link maps
// directly (#6740). Each takes m.mu and releases it immediately, so a caller
// can do its netlink/BPF work between a read and the matching write without
// ever holding the lock across a syscall — which is exactly the shape
// DetachXDP needs (read the link, Close() it unlocked, then delete the entry).

// markVLANSubInterfaces records the generic-XDP, non-tunnel ifindexes of a
// compile as VLAN sub-interfaces, under m.mu (#6740).
//
// SINGLE-SOURCED on purpose. CompileUserspaceShim and Compile carried two
// identical copies of this loop, and a divergence between them is always a bug:
// both feed the same vlanSubInterfaces map that the entry-program swap and the
// 1 Hz status path read. One definition also makes the lock testable — a
// concurrent regression can call this directly, where it cannot drive
// CompileUserspaceShim without a full config and real syscalls.
//
// The caller's attach work has completed by the time this runs, so no netlink
// or BPF syscall is held under the lock.
func (m *Manager) markVLANSubInterfaces(result *CompileResult) {
	if result == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for ifidx := range result.genericXDPIfindexes {
		if !result.tunnelIfindexes[ifidx] {
			m.vlanSubInterfaces[ifidx] = true
		}
	}
}

func (m *Manager) xdpLinkFor(ifindex int) (link.Link, bool) {
	// #9337: DetachXDP's FIRST contended m.mu acquisition. It was not always:
	// before the link maps were guarded (01409c1f, 2026-08-22) DetachXDP read
	// m.xdpLinks unlocked and its first block was the PROBED lookupMapLocked
	// inside setXDPAttachedFlag. Moving the acquisition ahead of that surface
	// silently invalidated TestManager_ArmedGate_DetachRetainedClaims' arrival
	// proof: the detach blocked here, the probe never fired, and the test's
	// `<-probeArrived` waited forever. It needs a real BPF map, so it SKIPS
	// unprivileged and the deadlock only appears under CAP_BPF — where it burnt
	// the whole 15-minute package budget and voided every later cell in
	// pkg/dataplane.
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("xdpLinkFor")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.xdpLinks[ifindex]
	return l, ok
}

func (m *Manager) setXDPLink(ifindex int, l link.Link) {
	m.mu.Lock()
	m.xdpLinks[ifindex] = l
	m.mu.Unlock()
	// #9725: an OPENING change reports AFTER it happens -- the link must exist
	// before the gate may open on it. Reported with m.mu released: the observer
	// does kernel work and re-reads the count.
	m.notifyAttachedLinksFunc(m.AttachedXDPLinkCount)
}

func (m *Manager) deleteXDPLink(ifindex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.xdpLinks, ifindex)
}

func (m *Manager) tcLinkFor(ifindex int) (link.Link, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.tcLinks[ifindex]
	return l, ok
}

func (m *Manager) setTCLink(ifindex int, l link.Link) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tcLinks[ifindex] = l
}

func (m *Manager) deleteTCLink(ifindex int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tcLinks, ifindex)
}

// SetLinkForTest records link membership without performing any attach, for
// tests that need attached-link state but cannot issue netlink/BPF syscalls.
//
// It exists because #6740 made XDPLinks/TCLinks return SNAPSHOTS: tests used to
// seed membership by writing through the returned map
// (`m.bpfShim.XDPLinks()[ifindex] = l`), which silently became a write to a
// throwaway copy. That is the correct trade — handing out the live map is what
// made the 1 Hz status path racy — but it removes the only seeding path a
// cross-package test had, so the seam is explicit rather than incidental.
//
// A nil link is recorded as-is: several arm-proof tests deliberately track an
// ifindex whose handle cannot be dereferenced.
func (m *Manager) SetLinkForTest(ifindex int, xdp, tc link.Link) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if xdp != nil {
		m.xdpLinks[ifindex] = xdp
	}
	if tc != nil {
		m.tcLinks[ifindex] = tc
	}
}

// IsVLANSubInterface reports whether this ifindex was recorded as a VLAN
// sub-interface, under m.mu (#6740).
func (m *Manager) IsVLANSubInterface(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vlanSubInterfaces[ifindex]
}
