// Test-only helpers for pkg/vrrp.Manager. They live in the production
// package so external package tests (such as pkg/daemon HA cells) can drive
// manager-owned state without opening sockets or mutating host networking.
// Not for production callers.
package vrrp

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
)

// SeedInstanceForTesting installs an instance with the requested state and
// configures this manager to preserve it through UpdateInstances without
// sockets, run-loop goroutines, or a host netlink address subscription. It is
// for tests that need reconcile to consume the manager's authoritative
// InstanceStates inventory rather than directly seeding a caller-side state
// machine. The supplied Instance must match the desired instance config used
// by UpdateInstances.
func (m *Manager) SeedInstanceForTesting(inst Instance, state VRRPState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	iface := &net.Interface{Name: inst.Interface, Index: 1}
	vi := newInstance(inst, iface, m.eventCh, m.onEventDrop)
	vi.setState(state)
	// No run goroutine exists for this fixture. Mark it stopped so the
	// lifecycle seam can safely tear it down through either UpdateInstances
	// or Manager.Stop without waiting for an unstarted goroutine.
	close(vi.stopped)
	m.instances[instanceKey{iface: inst.Interface, groupID: inst.GroupID, family: inst.Family}] = vi
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 1}, nil
	}
	m.openInstanceSocket = func(*vrrpInstance) error { return nil }
	m.runInstance = func(vi *vrrpInstance) { close(vi.stopped) }
	m.stopInstance = func(vi *vrrpInstance) { vi.stop() }
	m.subscribeAddrs = func(chan<- netlink.AddrUpdate, <-chan struct{}) error {
		return errors.New("address watcher disabled by test fixture")
	}
}
