package vrrp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #1814 — interface tracking: effective priority, setTrackDown,
// UpdateInstances track-field propagation, and the singleton link
// watcher. All tests use the injectable linkState/subscribeLinks seams;
// none require real netlink.

// stopManagerForTest clears manually-injected instances before Stop().
// vi.stop() blocks on <-vi.stopped, which only run() closes — and test
// instances are never run. Clearing the map first lets Stop() shut down
// the link watcher and event channel without hanging.
func stopManagerForTest(m *Manager) {
	m.mu.Lock()
	m.instances = make(map[instanceKey]*vrrpInstance)
	m.mu.Unlock()
	m.Stop()
}

func newTrackTestInstance(pri, cost int, track string) *vrrpInstance {
	return newInstance(Instance{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          pri,
		TrackInterface:    track,
		TrackPriorityCost: cost,
	}, &net.Interface{Name: "eth0"}, make(chan VRRPEvent, 16), nil)
}

func TestGetPriority_TrackMatrix(t *testing.T) {
	tests := []struct {
		name      string
		pri       int
		cost      int
		track     string
		trackDown bool
		want      int
	}{
		{"no-track-config-down-flag", 200, 50, "", true, 200},
		{"tracked-up", 200, 50, "ge-0-0-1", false, 200},
		{"tracked-down-subtract", 200, 50, "ge-0-0-1", true, 150},
		{"cost-equals-priority-clamp-1", 100, 100, "ge-0-0-1", true, 1},
		{"cost-exceeds-priority-clamp-1", 100, 250, "ge-0-0-1", true, 1},
		{"zero-cost-down-unchanged", 200, 0, "ge-0-0-1", true, 200},
		{"priority-0-resign-passthrough", 0, 50, "ge-0-0-1", true, 0},
		{"priority-255-owner-exempt", 255, 50, "ge-0-0-1", true, 255},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vi := newTrackTestInstance(tt.pri, tt.cost, tt.track)
			vi.setTrackDown(tt.trackDown)
			if got := vi.getPriority(); got != tt.want {
				t.Errorf("getPriority() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSetTrackDown_Transition(t *testing.T) {
	vi := newTrackTestInstance(200, 50, "ge-0-0-1")

	if vi.getPriority() != 200 {
		t.Fatalf("initial priority = %d, want 200", vi.getPriority())
	}

	vi.setTrackDown(true)
	vi.mu.RLock()
	down := vi.trackDown
	vi.mu.RUnlock()
	if !down {
		t.Fatal("trackDown not set")
	}
	if vi.getPriority() != 150 {
		t.Errorf("priority after down = %d, want 150", vi.getPriority())
	}

	// Idempotent re-apply keeps state.
	vi.setTrackDown(true)
	if vi.getPriority() != 150 {
		t.Errorf("priority after repeated down = %d, want 150", vi.getPriority())
	}

	vi.setTrackDown(false)
	if vi.getPriority() != 200 {
		t.Errorf("priority after recovery = %d, want 200", vi.getPriority())
	}
}

func TestCollectInstances_TrackInterfaceNormalized(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {
					Name: "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							VRRPGroups: map[string]*config.VRRPGroup{
								"10.0.0.1/24_grp1": {
									ID:                 1,
									Priority:           200,
									VirtualAddresses:   []string{"10.0.0.3/24"},
									TrackInterface:     "ge-0/0/1",
									TrackPriorityDelta: 20,
								},
							},
						},
					},
				},
			},
		},
	}
	instances := CollectInstances(cfg)
	if len(instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(instances))
	}
	if instances[0].TrackInterface != "ge-0-0-1" {
		t.Errorf("TrackInterface = %q, want ge-0-0-1 (Linux-normalized)", instances[0].TrackInterface)
	}
	if instances[0].TrackPriorityCost != 20 {
		t.Errorf("TrackPriorityCost = %d, want 20", instances[0].TrackPriorityCost)
	}
}

func TestUpdateInstances_TrackFieldChangeInPlace(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	// Pin resolveIface so the #2294 ifindex-drift probe is hermetic
	// regardless of whether the host has a real eth0 (mirrors the
	// vrrp_test.go:591 stub): return the same Index (0) the seeded
	// instance binds, so no drift is detected.
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 0}, nil
	}
	m.linkState = func(name string) (bool, error) {
		if name == "ge-0-0-9" {
			return false, nil // tracked interface is down
		}
		return true, nil
	}
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return nil // never sends — seeding is what's under test
	}
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }

	vi := newInstance(Instance{
		Interface: "eth0",
		GroupID:   101,
		Priority:  200,
		Preempt:   true,
	}, &net.Interface{Name: "eth0"}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = vi
	m.mu.Unlock()

	desired := []*Instance{{
		Interface:         "eth0",
		GroupID:           101,
		Priority:          200,
		Preempt:           true,
		TrackInterface:    "ge-0-0-9",
		TrackPriorityCost: 50,
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	vi.mu.RLock()
	gotIface := vi.cfg.TrackInterface
	gotCost := vi.cfg.TrackPriorityCost
	gotDown := vi.trackDown
	vi.mu.RUnlock()
	if gotIface != "ge-0-0-9" || gotCost != 50 {
		t.Errorf("track config = %q/%d, want ge-0-0-9/50 (in-place update)", gotIface, gotCost)
	}
	if !gotDown {
		t.Error("trackDown not seeded from linkState on track-field change")
	}
	if got := vi.getPriority(); got != 150 {
		t.Errorf("effective priority = %d, want 150", got)
	}

	// Removing tracking via a second update clears the demotion.
	desired[0].TrackInterface = ""
	desired[0].TrackPriorityCost = 0
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances(clear): %v", err)
	}
	if got := vi.getPriority(); got != 200 {
		t.Errorf("effective priority after clearing tracking = %d, want 200", got)
	}
}

func TestLinkWatcher_Singleton(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	m.linkState = func(string) (bool, error) { return true, nil }
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return nil // never sends
	}
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }

	desired := []*Instance{{
		Interface:         "no-such-iface-xyz0", // creation skipped; watcher still latches
		GroupID:           101,
		Priority:          200,
		TrackInterface:    "ge-0-0-9",
		TrackPriorityCost: 10,
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #1: %v", err)
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances #2: %v", err)
	}

	m.mu.RLock()
	starts := m.watcherStarts
	running := m.watcherRunning
	m.mu.RUnlock()
	if starts != 1 {
		t.Errorf("watcherStarts = %d, want 1 (singleton)", starts)
	}
	if !running {
		t.Error("watcherRunning should be latched")
	}
}

func TestLinkWatcher_EventUpdatesTrackedInstances(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	m.linkState = func(string) (bool, error) { return true, nil }

	updates := make(chan chan<- netlink.LinkUpdate, 1)
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}

	tracker := newTrackTestInstance(200, 50, "ge-0-0-9")
	other := newTrackTestInstance(200, 50, "ge-0-0-8")
	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = tracker
	m.instances[instanceKey{iface: "eth1", groupID: 102}] = other
	m.ensureLinkWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.LinkUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never subscribed")
	}

	// Link down event for ge-0-0-9 → only the tracker is demoted.
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9", OperState: netlink.OperDown}},
	}
	deadline := time.After(2 * time.Second)
	for tracker.getPriority() != 150 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 150 after link-down event", tracker.getPriority())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := other.getPriority(); got != 200 {
		t.Errorf("non-matching instance priority = %d, want 200", got)
	}

	// RTM_DELLINK counts as down even with OperUp attrs; recovery via
	// a NEWLINK OperUp event restores priority.
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9", OperState: netlink.OperUp}},
	}
	deadline = time.After(2 * time.Second)
	for tracker.getPriority() != 200 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 200 after link-up event", tracker.getPriority())
		case <-time.After(10 * time.Millisecond):
		}
	}
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9", OperState: netlink.OperUp}},
	}
	deadline = time.After(2 * time.Second)
	for tracker.getPriority() != 150 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 150 after DELLINK", tracker.getPriority())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestLinkWatcher_RenameAwayDemotes covers #2944: a runtime kernel rename of a
// tracked interface (wan0 -> wan1) arrives as a SINGLE RTM_NEWLINK carrying the
// SAME ifindex with the NEW name and NO RTM_DELLINK for the old name. An
// instance tracking the configured name (wan0) must DEMOTE because the named
// interface no longer exists — it must NOT silently follow the ifindex to wan1
// and stay up. Reverting applyLinkEvent to the old name-only matching makes the
// rename event match nothing and the tracker stays at full priority (RED).
func TestLinkWatcher_RenameAwayDemotes(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	// wan0 no longer resolves after the rename (LinkByName fails -> down); any
	// other name is up. This is what the kernel does post-rename.
	m.linkState = func(name string) (bool, error) {
		if name == "wan0" {
			return false, errors.New("no such link")
		}
		return true, nil
	}

	updates := make(chan chan<- netlink.LinkUpdate, 1)
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		updates <- ch
		return nil
	}
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }

	tracker := newTrackTestInstance(200, 50, "wan0")
	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = tracker
	m.ensureLinkWatcherLocked()
	m.mu.Unlock()

	var ch chan<- netlink.LinkUpdate
	select {
	case ch = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never subscribed")
	}

	const ifindex = 5
	// First sighting at ifindex 5 with the configured name wan0, up. Represents
	// the ListExisting seed / a prior up event; warms the ifindex->name cache.
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: ifindex, Name: "wan0", OperState: netlink.OperUp}},
	}
	// Settle: tracker should be up (priority 200) after the wan0-up event.
	deadline := time.After(2 * time.Second)
	for tracker.getPriority() != 200 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 200 after wan0 up event", tracker.getPriority())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// The rename: SAME ifindex, NEW name wan1, still OperUp, NO RTM_DELLINK for
	// wan0. The instance tracking wan0 must demote.
	ch <- netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
		Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: ifindex, Name: "wan1", OperState: netlink.OperUp}},
	}
	deadline = time.After(2 * time.Second)
	for tracker.getPriority() != 150 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 150 after wan0 renamed away to wan1", tracker.getPriority())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestPollTrackedLinks(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	state := map[string]bool{"ge-0-0-9": false}
	m.linkState = func(name string) (bool, error) {
		up, ok := state[name]
		if !ok {
			return false, errors.New("no such link")
		}
		return up, nil
	}

	tracker := newTrackTestInstance(200, 50, "ge-0-0-9")
	missing := newTrackTestInstance(200, 30, "gone0")
	untracked := newTrackTestInstance(200, 50, "")
	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = tracker
	m.instances[instanceKey{iface: "eth1", groupID: 102}] = missing
	m.instances[instanceKey{iface: "eth2", groupID: 103}] = untracked
	m.mu.Unlock()

	m.pollTrackedLinks()
	if got := tracker.getPriority(); got != 150 {
		t.Errorf("tracker priority = %d, want 150 (link down)", got)
	}
	if got := missing.getPriority(); got != 170 {
		t.Errorf("missing-link priority = %d, want 170 (lookup error counts as down)", got)
	}
	if got := untracked.getPriority(); got != 200 {
		t.Errorf("untracked priority = %d, want 200", got)
	}

	// Link recovers — next poll restores.
	state["ge-0-0-9"] = true
	m.pollTrackedLinks()
	if got := tracker.getPriority(); got != 200 {
		t.Errorf("tracker priority after recovery = %d, want 200", got)
	}
}

func TestLinkWatcher_SubscribeFailureFallsBackToPolling(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	m.linkState = func(name string) (bool, error) { return false, nil } // always down
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		return errors.New("subscribe denied")
	}

	tracker := newTrackTestInstance(200, 50, "ge-0-0-9")
	m.mu.Lock()
	m.instances[instanceKey{iface: "eth0", groupID: 101}] = tracker
	m.ensureLinkWatcherLocked()
	m.mu.Unlock()

	deadline := time.After(3 * time.Second)
	for tracker.getPriority() != 150 {
		select {
		case <-deadline:
			t.Fatalf("tracker priority = %d, want 150 via 1s poll fallback", tracker.getPriority())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestUpdateInstances_NoTrackNoWatcher(t *testing.T) {
	m := NewManager()
	defer stopManagerForTest(m)
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		t.Error("watcher must not start without tracked instances")
		return nil
	}
	m.subscribeAddrs = func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error { return nil }
	desired := []*Instance{{
		Interface: "no-such-iface-xyz0",
		GroupID:   101,
		Priority:  200,
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}
	m.mu.RLock()
	running := m.watcherRunning
	m.mu.RUnlock()
	if running {
		t.Error("watcher started with no tracked instances")
	}
}
