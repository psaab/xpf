package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPrepareSnapshotForApplyRebuildsDerivedIfindexes14209 pins #14209:
// prepareSnapshotForApply revalidates Interfaces in place (a link recreated
// between build and apply resolves to a new ifindex, or vanishes), but the
// sections derived from the OLD interface rows at build time —
// TunnelEndpoints, MirrorConfigs/MirrorExclusions, Routes and Fabrics —
// kept the stale ifindexes. The published snapshot then carried a current
// ingress row joined to a stale tunnel/mirror egress (Rust consumes the
// tunnel endpoint's own ifindex), so traffic was dropped or misattributed.
//
// FAIL-ON-REVERT: reverting the derived-section rebuild in
// prepareSnapshotForApply leaves TunnelEndpoints[0].Ifindex at the stale
// build-time value (and the vanished interface's mirror/connected route
// installed), so the assertions below go RED.
func TestPrepareSnapshotForApplyRebuildsDerivedIfindexes14209(t *testing.T) {
	origBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = origBuild })
	// Kernel state at apply time: ge-0-0-0 was recreated (17 -> 29),
	// ge-0-0-1 vanished, gr-0-0-0 and ge-0-0-9 are unchanged.
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
	origXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = origXfrm })
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }

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

	// Snapshot as built BEFORE the churn: stale ifindexes 17 (recreated)
	// and 18 (vanished) baked into every derived section.
	snap := &ConfigSnapshot{
		Config: cfg,
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/0.0", LinuxName: "ge-0-0-0", Ifindex: 17, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.0.1/24"}}},
			{Name: "ge-0/0/1.0", LinuxName: "ge-0-0-1", Ifindex: 18, Addresses: []InterfaceAddressSnapshot{{Family: "inet", Address: "10.0.1.1/24"}}},
			{Name: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, MTU: 1476},
			{Name: "ge-0/0/9", LinuxName: "ge-0-0-9", Ifindex: 19},
		},
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{Interface: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, Mode: "gre"},
		},
		// The tunnel endpoint joins by its own ifindex; give the recreated
		// interface's derived rows the stale value by also covering a
		// tunnel on ge-0/0/0 via the mirror/route rows below. The tunnel
		// row itself is rebuilt from the revalidated rows.
		MirrorConfigs: []MirrorConfigSnapshot{
			{IngressIfindex: 17, OutputIfindex: 19},
			{IngressIfindex: 18, OutputIfindex: 19},
		},
		Routes: []RouteSnapshot{
			{Table: "inet.0", Family: "inet", Destination: "10.0.0.0/24"},
			{Table: "inet.0", Family: "inet", Destination: "10.0.1.0/24"},
		},
	}

	m := &Manager{}
	m.prepareSnapshotForApply(snap)

	// Interfaces: the config rebuild emits base+unit rows; the vanished
	// interface's rebuilt rows are dropped by the in-place revalidation,
	// leaving the 5 surviving rows (#14333).
	if len(snap.Interfaces) != 5 {
		t.Fatalf("interfaces = %+v, want 5 surviving rows", snap.Interfaces)
	}
	for _, row := range snap.Interfaces {
		if row.LinuxName == "ge-0-0-0" && row.Ifindex != 29 {
			t.Fatalf("recreated interface ifindex = %d, want 29", row.Ifindex)
		}
		if row.LinuxName == "ge-0-0-1" {
			t.Fatalf("vanished interface survived revalidation: %+v", row)
		}
	}

	// TunnelEndpoints rebuilt against the revalidated rows.
	if len(snap.TunnelEndpoints) != 1 || snap.TunnelEndpoints[0].Ifindex != 42 {
		t.Fatalf("tunnel endpoints = %+v, want the gr endpoint at ifindex 42", snap.TunnelEndpoints)
	}

	// Mirrors: recreated ingress follows to 29; vanished ingress is
	// excluded (recorded), not published with the stale ifindex.
	if len(snap.MirrorConfigs) != 1 || snap.MirrorConfigs[0].IngressIfindex != 29 || snap.MirrorConfigs[0].OutputIfindex != 19 {
		t.Fatalf("mirror configs = %+v, want one mirror 29 -> 19", snap.MirrorConfigs)
	}
	foundExclusion := false
	for _, ex := range snap.MirrorExclusions {
		if ex.Instance == "m2" {
			foundExclusion = true
		}
	}
	if !foundExclusion {
		t.Fatalf("mirror exclusions = %+v, want m2 recorded as excluded", snap.MirrorExclusions)
	}

	// Routes: the vanished interface's connected route is gone; the
	// recreated interface's connected route remains.
	for _, r := range snap.Routes {
		if r.Destination == "10.0.1.0/24" {
			t.Fatalf("connected route for vanished interface still published: %+v", snap.Routes)
		}
	}
	foundConnected := false
	for _, r := range snap.Routes {
		if r.Destination == "10.0.0.0/24" {
			foundConnected = true
		}
	}
	if !foundConnected {
		t.Fatalf("connected route for recreated interface missing: %+v", snap.Routes)
	}
}

// TestPrepareSnapshotForApplyRebuildsTunnelIfindex14209 is the narrow
// tunnel-endpoint form of the decisive fixture: the tunnel netdev itself
// is recreated between build and apply, so the endpoint's own ifindex —
// the value Rust joins on — must move with the interface row.
func TestPrepareSnapshotForApplyRebuildsTunnelIfindex14209(t *testing.T) {
	origBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = origBuild })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "gr-0-0-0" {
			return 77, 1476, "", nil // recreated: was 42, now 77
		}
		return 0, 0, "", nil
	}
	origXfrm := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = origXfrm })
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, nil }

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
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
	}
	snap := &ConfigSnapshot{
		Config: cfg,
		Interfaces: []InterfaceSnapshot{
			{Name: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, MTU: 1476},
		},
		TunnelEndpoints: []TunnelEndpointSnapshot{
			{Interface: "gr-0/0/0.0", LinuxName: "gr-0-0-0", Ifindex: 42, Mode: "gre"},
		},
	}

	m := &Manager{}
	m.prepareSnapshotForApply(snap)

	if len(snap.Interfaces) != 2 {
		t.Fatalf("interfaces = %+v, want rebuilt base+unit gr rows", snap.Interfaces)
	}
	for _, row := range snap.Interfaces {
		if row.Ifindex != 77 {
			t.Fatalf("interfaces = %+v, want gr rows refreshed to 77", snap.Interfaces)
		}
	}
	if len(snap.TunnelEndpoints) != 1 || snap.TunnelEndpoints[0].Ifindex != 77 {
		t.Fatalf("tunnel endpoints = %+v, want endpoint ifindex rebuilt to 77 (#14209)", snap.TunnelEndpoints)
	}
}
