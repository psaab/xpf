package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestRepublishRetainsRebuiltDerivedSections15043 pins A29-02 (#15043).
//
// Every partial republish sends through prepareSnapshotForApply, which
// revalidates Interfaces and, when a row moved, rebuilds the derived
// sections (#14209): Interfaces, Routes, Fabrics, TunnelEndpoints,
// MirrorConfigs/MirrorExclusions, the zone quarantine and its validated
// flag. The scheduler, deferred-worker-arm and status-tick paths then
// retained only publishSnap.Interfaces (plus Neighbors/Fabrics when
// resampled), so m.lastSnapshot kept the STALE derived sections while
// lastSnapshotHash was taken from the rebuilt publishSnap. Publish #2
// therefore started from the stale struct and re-shipped a vanished or
// reused ifindex in its mirror/tunnel/route rows, while the hash
// invariant (lastSnapshotHash == hash(lastSnapshot)) was already broken
// after publish #1.
//
// FAIL-ON-REVERT: restoring any of the three Interfaces-only write-backs
// (or taking the hash from publishSnap while retaining next) leaves the
// retained snapshot's MirrorConfigs at the stale build-time ifindex 17
// and breaks the hash invariant asserted below.
func TestRepublishRetainsRebuiltDerivedSections15043(t *testing.T) {
	origBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = origBuild })
	origLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = origLookup })
	origXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = origXfrm })
	// Kernel state at publish time: ge-0-0-0 was recreated (17 -> 29) and
	// ge-0-0-1 vanished; gr-0-0-0 and ge-0-0-9 are unchanged. This is the
	// #14209 fixture's apply-time sample, so the rebuild moves every
	// derived ifindex off the stale build-time rows.
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-0":
			return 29, 1500, "", nil
		case "gr-0-0-0":
			return 42, 1476, "", nil
		case "ge-0-0-9":
			return 19, 1500, "", nil
		default:
			return 0, 0, "", nil
		}
	}
	linkByNameFn = func(string) (netlink.Link, error) { return nil, errors.New("test link lookup") }
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }

	cfg := republishDerivedConfig15043()

	newManager := func(t *testing.T) (*Manager, *[]*ConfigSnapshot) {
		t.Helper()
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		// Seam the status-sync maps so a landed publish returns nil
		// instead of a map-not-loaded error (the #9337 fixture pattern).
		m.helperStatusCtrlMapHook = &fakeCtrlMap{}
		m.helperStatusBindingsMapHook = &fakeBindingsMap{}
		m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
		m.clearHelperHAStateHook = func() error { return nil }
		m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
		m.helperStatusObserved = true
		m.lastSnapshot = republishDerivedSnapshot15043(cfg)
		m.generation = 7
		m.publishedSnapshot = 7
		m.publishedPlanKey = snapshotBindingPlanKey(m.lastSnapshot)
		if h, ok := snapshotContentHash(m.lastSnapshot); ok {
			m.lastSnapshotHash = h
		} else {
			t.Fatal("fixture: retained snapshot must hash")
		}
		var sent []*ConfigSnapshot
		m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
			if req.Type == "apply_snapshot" {
				c := *req.Snapshot
				sent = append(sent, &c)
			}
			return nil
		}
		return m, &sent
	}

	assertRetained := func(t *testing.T, m *Manager, sent *ConfigSnapshot) {
		t.Helper()
		if sent == nil {
			t.Fatal("premise: publish sent no apply_snapshot")
		}
		// The sent snapshot is the rebuilt one (#14209): the recreated
		// interface's mirror follows to 29, the vanished interface's
		// mirror is excluded, and its connected route is gone.
		if len(sent.MirrorConfigs) != 1 || sent.MirrorConfigs[0].IngressIfindex != 29 {
			t.Fatalf("premise: sent mirrors = %+v, want the rebuilt 29 mirror", sent.MirrorConfigs)
		}
		// The retained snapshot must be exactly what was sent, derived
		// sections included — not the stale pre-rebuild rows.
		retained := m.lastSnapshot
		if len(retained.Interfaces) != len(sent.Interfaces) {
			t.Errorf("retained interfaces = %+v, want sent %+v", retained.Interfaces, sent.Interfaces)
		}
		if len(retained.MirrorConfigs) != 1 || retained.MirrorConfigs[0].IngressIfindex != 29 ||
			retained.MirrorConfigs[0].OutputIfindex != 19 {
			t.Errorf("retained mirrors = %+v, want the rebuilt 29 -> 19 mirror the helper accepted (#15043)", retained.MirrorConfigs)
		}
		foundExclusion := false
		for _, ex := range retained.MirrorExclusions {
			if ex.Instance == "m2" {
				foundExclusion = true
			}
		}
		if !foundExclusion {
			t.Errorf("retained mirror exclusions = %+v, want m2 recorded as excluded (#15043)", retained.MirrorExclusions)
		}
		if len(retained.TunnelEndpoints) != 1 || retained.TunnelEndpoints[0].Ifindex != 42 {
			t.Errorf("retained tunnel endpoints = %+v, want the rebuilt endpoint at 42 (#15043)", retained.TunnelEndpoints)
		}
		for _, r := range retained.Routes {
			if r.Destination == "10.0.1.0/24" {
				t.Errorf("retained routes still carry the vanished interface's connected route: %+v (#15043)", retained.Routes)
			}
		}
		foundConnected := false
		for _, r := range retained.Routes {
			if r.Destination == "10.0.0.0/24" {
				foundConnected = true
			}
		}
		if !foundConnected {
			t.Errorf("retained routes = %+v, want the recreated interface's connected route (#15043)", retained.Routes)
		}
		// Hash invariant: the stored hash describes the retained struct.
		if h, ok := snapshotContentHash(retained); !ok || h != m.lastSnapshotHash {
			t.Errorf("hash invariant broken after publish: hash(retained)=%x ok=%v stored=%x (#15043)", h, ok, m.lastSnapshotHash)
		}
		if got, want := snapshotBindingPlanKey(retained), m.publishedPlanKey; got != want {
			t.Errorf("retained plan key %q != published plan key %q (#15043)", got, want)
		}
	}

	t.Run("scheduler", func(t *testing.T) {
		m, sent := newManager(t)
		if err := m.UpdatePolicyScheduleStateWithLatch(cfg, map[string]bool{}, false); err != nil {
			t.Fatalf("scheduler republish: %v", err)
		}
		if len(*sent) != 1 {
			t.Fatalf("premise: scheduler sent %d snapshots, want 1", len(*sent))
		}
		assertRetained(t, m, (*sent)[0])
		// Publish #2 must carry the rebuilt rows, not resurrect the
		// stale mirror/route rows from the retained struct.
		if err := m.UpdatePolicyScheduleStateWithLatch(cfg, map[string]bool{}, false); err != nil {
			t.Fatalf("scheduler republish #2: %v", err)
		}
		if len(*sent) != 2 {
			t.Fatalf("premise: scheduler sent %d snapshots, want 2", len(*sent))
		}
		second := (*sent)[1]
		if len(second.MirrorConfigs) != 1 || second.MirrorConfigs[0].IngressIfindex != 29 {
			t.Errorf("publish #2 mirrors = %+v, want the rebuilt 29 mirror, not the stale 17 row (#15043)", second.MirrorConfigs)
		}
		for _, r := range second.Routes {
			if r.Destination == "10.0.1.0/24" {
				t.Errorf("publish #2 resurrected the vanished interface's connected route: %+v (#15043)", second.Routes)
			}
		}
	})

	t.Run("deferred-worker-arm", func(t *testing.T) {
		m, sent := newManager(t)
		m.lastSnapshot.DeferWorkers = true
		m.pendingWorkerArm = true
		m.mu.Lock()
		err := m.retryDeferredWorkerArmLocked()
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("deferred-worker-arm republish: %v", err)
		}
		if len(*sent) != 1 {
			t.Fatalf("premise: worker-arm sent %d snapshots, want 1", len(*sent))
		}
		assertRetained(t, m, (*sent)[0])
		if m.lastSnapshot.DeferWorkers {
			t.Error("retained snapshot still defers workers after a successful arm")
		}
	})

	t.Run("status-tick", func(t *testing.T) {
		m, sent := newManager(t)
		// The deferred snapshot is retained ahead of its publication:
		// publishedSnapshot stays behind, so the tick publishes it.
		m.publishedSnapshot = 0
		m.publishedPlanKey = ""
		m.lastSnapshot.Generation = 8
		m.generation = 8
		m.mu.Lock()
		err := m.syncSnapshotLocked()
		m.mu.Unlock()
		if err != nil {
			t.Fatalf("status-tick republish: %v", err)
		}
		if len(*sent) != 1 {
			t.Fatalf("premise: status tick sent %d snapshots, want 1", len(*sent))
		}
		assertRetained(t, m, (*sent)[0])
	})
}

// republishDerivedConfig15043 is the #14209 fixture config: two addressed
// interfaces (one recreated, one vanished at publish time), a GRE tunnel
// and two mirror instances.
func republishDerivedConfig15043() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
			},
		},
		"ge-0/0/1": {
			Name: "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
			},
		},
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "192.0.2.1",
				Destination: "192.0.2.2",
			},
		},
		"ge-0/0/9": {Name: "ge-0/0/9"},
	}
	cfg.ForwardingOptions.PortMirroring = &config.PortMirroringConfig{
		Instances: map[string]*config.PortMirrorInstance{
			"m1": {Name: "m1", Output: "ge-0/0/9", Input: []string{"ge-0/0/0"}},
			"m2": {Name: "m2", Output: "ge-0/0/9", Input: []string{"ge-0/0/1"}},
		},
	}
	return cfg
}

// republishDerivedSnapshot15043 is the snapshot as built BEFORE the link
// churn: stale ifindexes 17 (recreated) and 18 (vanished) baked into every
// derived section.
func republishDerivedSnapshot15043(cfg *config.Config) *ConfigSnapshot {
	return &ConfigSnapshot{
		Version:    ProtocolVersion,
		Generation: 7,
		Config:     cfg,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 17, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}}},
			{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 18, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.1/24"}}},
			{Name: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, MTU: 1476},
			{Name: "ge-0/0/9", LinuxName: "ge-0-0-9", Ifindex: 19},
		},
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{Interface: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, Mode: "gre"},
		},
		MirrorConfigs: []MirrorConfigSnapshot{
			{IngressIfindex: 17, OutputIfindex: 19},
			{IngressIfindex: 18, OutputIfindex: 19},
		},
		Routes: []RouteSnapshot{
			{Table: "inet.0", Family: "inet", Destination: "10.0.0.0/24"},
			{Table: "inet.0", Family: "inet", Destination: "10.0.1.0/24"},
		},
	}
}
