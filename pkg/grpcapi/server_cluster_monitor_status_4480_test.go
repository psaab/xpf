package grpcapi

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/routing"
)

// clusterMonitorStore commits a chassis cluster carrying a single
// redundancy-group with the given interface-monitor stanza body. The
// interface-monitor lines are appended verbatim (e.g. "lo weight 255;").
func clusterMonitorStore(t *testing.T, monitorBody string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	cfg := `
system {
    host-name day0-test;
}
interfaces {
    fxp0 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}
chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        redundancy-group 1 {
            node 0 priority 100;
            node 1 priority 1;
            interface-monitor {
` + monitorBody + `
            }
        }
    }
}
`
	if err := store.LoadOverride(cfg); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestBuildInterfacesInputLocalMonitorFallbackHonest pins #4480: when no live
// interface-monitor status is available for a redundancy group (the routing
// sweep has not produced a link-state result — here s.routing is nil), the
// local monitor display must surface the honest "unknown as Down" (Up=false),
// NOT the former hardcoded Up=true that let a DOWN monitored uplink render as
// healthy (an observability lie). This matches the peer branch's config-only
// fill, which already reports Up=false.
//
// RED-on-revert: reverting the fix restores Up=true here and this test fails.
func TestBuildInterfacesInputLocalMonitorFallbackHonest(t *testing.T) {
	// A monitor on an interface that does not exist locally; with s.routing
	// nil there is no live status for the RG at all, so buildInterfacesInput
	// takes the config-only local fallback branch.
	store := clusterMonitorStore(t, "                ge-9/0/9 weight 255;")

	s := &Server{store: store} // routing nil, cluster nil

	input := s.buildInterfacesInput()

	if len(input.Monitors) != 1 {
		t.Fatalf("Monitors = %d, want 1 (%+v)", len(input.Monitors), input.Monitors)
	}
	mon := input.Monitors[0]
	if mon.Interface != "ge-9/0/9" {
		t.Errorf("monitor interface = %q, want ge-9/0/9", mon.Interface)
	}
	if mon.Up {
		t.Errorf("local monitor with unavailable live status Up = true, want false "+
			"(#4480 observability lie: a DOWN uplink must not render healthy); mon=%+v", mon)
	}
}

// TestBuildInterfacesInputLiveStatusFaithfulAndPeerHonest guards the two
// branches the #4480 fix must NOT disturb:
//
//   - The LOCAL live-status branch still faithfully copies the routing sweep's
//     Up value — an actually-up monitor still shows Up (the fix only touches
//     the config-only fallback, never the live path).
//   - The PEER config-only fill still honestly reports Up=false for a
//     peer-owned monitor interface (unchanged by #4480).
func TestBuildInterfacesInputLiveStatusFaithfulAndPeerHonest(t *testing.T) {
	// The strict gate (#15037) rejects a monitor naming "lo" (no FPC
	// slot, no netdev attribution), so the live local monitor is
	// ge-0/0/0; where no such netdev exists the sweep reports no
	// status and the test skips, as it did for a down loopback.
	// "ge-7/0/9" is the peer node's interface and never resolves locally.
	store := clusterMonitorStore(t,
		"                ge-0/0/0 weight 255;\n                ge-7/0/9 weight 200;")

	rm, err := routing.New()
	if err != nil {
		t.Skipf("routing.New(): %v (netlink unavailable in this environment)", err)
	}
	defer rm.Close()
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("active config missing chassis cluster")
	}
	rm.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)

	var liveLoUp bool
	var sawLo bool
	for _, sts := range rm.InterfaceMonitorStatuses() {
		for _, st := range sts {
			if st.Interface == "ge-0/0/0" {
				sawLo = true
				liveLoUp = st.Up
			}
		}
	}
	if !sawLo {
		t.Skip("ge-0/0/0 not resolvable as a live monitor in this environment")
	}
	if !liveLoUp {
		t.Skip("ge-0/0/0 reported operationally down in this environment")
	}

	s := &Server{
		store:   store,
		routing: rm,
		cluster: cluster.NewManager(0, 1), // no live peer heartbeat -> peerMonitors nil
	}

	input := s.buildInterfacesInput()

	var loMon *cluster.InterfaceMonitorInfo
	for i := range input.Monitors {
		if input.Monitors[i].Interface == "ge-0/0/0" {
			loMon = &input.Monitors[i]
		}
	}
	if loMon == nil {
		t.Fatalf("local monitor for 'ge-0/0/0' missing; Monitors=%+v", input.Monitors)
	}
	if !loMon.Up {
		t.Errorf("live-up local monitor Up = false, want true (fix must not force live status down); mon=%+v", *loMon)
	}

	// Peer branch (unchanged): the peer-owned "ge-7/0/9" has no local live
	// status and is filled honestly as Up=false.
	var peerMon *cluster.InterfaceMonitorInfo
	for i := range input.PeerMonitors {
		if input.PeerMonitors[i].Interface == "ge-7/0/9" {
			peerMon = &input.PeerMonitors[i]
		}
	}
	if peerMon == nil {
		t.Fatalf("peer monitor for 'ge-7/0/9' missing; PeerMonitors=%+v", input.PeerMonitors)
	}
	if peerMon.Up {
		t.Errorf("peer config-only monitor Up = true, want false (peer branch must stay honest); mon=%+v", *peerMon)
	}
}
