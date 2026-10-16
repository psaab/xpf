package daemon

// #14138: interface settings and OSPF.
//
// assembleFRRConfig collapsed every unit's PointToPoint flag onto the
// PARENT kernel name (config.LinuxIfName(name)): a point-to-point flag on
// a tagged unit (ge-0/0/1 unit 50, vlan-id 50) marked the untagged parent
// device — where the broadcast unit 0 lives — and never marked the actual
// VLAN netdev ge-0-0-1.50 that FRR/OSPF binds. A RETH logical name was
// likewise emitted verbatim instead of its local physical member's
// device. The per-unit kernel name is cfg.ResolveKernelIfName("<name>.<unit>"),
// the canonical resolver the protocol operands already use (#9405).
//
// Separately, generateInterfaceSettings' explicit-network-type suppression
// inspected only the GLOBAL OSPF config: an explicit network type under a
// routing-instance (VRF) OSPF area did not suppress the generated
// point-to-point line, so one interface could carry both.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func interfaceSettingsConfig14138() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {
				Name:      "ge-0/0/1",
				Bandwidth: 1_000_000_000,
				Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0},
					50: {Number: 50, VlanID: 50, PointToPoint: true},
				},
			},
			// Local physical member of reth1.
			"ge-0/0/3": {
				Name:            "ge-0/0/3",
				RedundantParent: "reth1",
				Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
			},
			"reth1": {
				Name:      "reth1",
				Bandwidth: 100_000_000,
				Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0},
					60: {Number: 60, VlanID: 60, PointToPoint: true},
				},
			},
		}},
		RoutingOptions: config.RoutingOptionsConfig{StaticRoutes: []*config.StaticRoute{
			{Destination: "192.0.2.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
		}},
	}
}

func TestAssembleFRRInterfaceSettingsPerUnit14138(t *testing.T) {
	fc := (&Daemon{}).assembleFRRConfig(interfaceSettingsConfig14138(), nil)

	wantP2P := map[string]bool{"ge-0-0-1.50": true, "ge-0-0-3.60": true}
	if len(fc.InterfacePointToPoint) != len(wantP2P) {
		t.Fatalf("InterfacePointToPoint = %v, want exactly %v (per-unit kernel devices, not parents)", fc.InterfacePointToPoint, wantP2P)
	}
	for dev := range wantP2P {
		if !fc.InterfacePointToPoint[dev] {
			t.Errorf("InterfacePointToPoint missing %q: got %v", dev, fc.InterfacePointToPoint)
		}
	}
	// Bandwidth is an interface-level property: it stays on the parent
	// device, resolved through the same kernel-name resolver (a RETH's
	// bandwidth lands on its local physical member, never on "reth1").
	if got := fc.InterfaceBandwidths["ge-0-0-1"]; got != 1_000_000_000 {
		t.Errorf("InterfaceBandwidths[ge-0-0-1] = %d, want 1000000000: %v", got, fc.InterfaceBandwidths)
	}
	if got := fc.InterfaceBandwidths["ge-0-0-3"]; got != 100_000_000 {
		t.Errorf("InterfaceBandwidths[ge-0-0-3] = %d, want 100000000 (reth1 resolved to its member): %v", got, fc.InterfaceBandwidths)
	}
	if _, ok := fc.InterfaceBandwidths["reth1"]; ok {
		t.Errorf("InterfaceBandwidths keyed by logical reth1 name: %v", fc.InterfaceBandwidths)
	}

	rendered := renderFRRConfig11310(t, fc)
	for _, want := range []string{
		"interface ge-0-0-1.50\n ip ospf network point-to-point\n",
		"interface ge-0-0-3.60\n ip ospf network point-to-point\n",
		"interface ge-0-0-1\n bandwidth 1000000\n",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered config missing %q:\n%s", want, rendered)
		}
	}
	// The broadcast unit 0 shares the parent device: no point-to-point
	// line may be attached to the parent or to the logical RETH name.
	if strings.Contains(rendered, "interface ge-0-0-1\n ip ospf network point-to-point") {
		t.Errorf("tagged unit 50 spuriously marked the parent device point-to-point:\n%s", rendered)
	}
	if strings.Contains(rendered, "interface reth1") || strings.Contains(rendered, "interface ge-0-0-3\n ip ospf network") {
		t.Errorf("RETH point-to-point unit rendered on a non-kernel device name:\n%s", rendered)
	}
	if n := strings.Count(rendered, " ip ospf network point-to-point\n"); n != 2 {
		t.Errorf("point-to-point lines = %d, want exactly 2 (one per tagged unit):\n%s", n, rendered)
	}
}

func TestAssembleFRRInstanceOSPFNetworkTypeSuppressesP2P14138(t *testing.T) {
	cfg := interfaceSettingsConfig14138()
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name:         "blue",
		InstanceType: "virtual-router",
		Interfaces:   []string{"ge-0/0/1.50"},
		OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{
			ID: "0.0.0.0",
			Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.50", NetworkType: "broadcast"},
			},
		}}},
	}}

	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	if !fc.InterfacePointToPoint["ge-0-0-1.50"] {
		t.Fatalf("precondition: InterfacePointToPoint = %v, want ge-0-0-1.50 present", fc.InterfacePointToPoint)
	}

	rendered := renderFRRConfig11310(t, fc)
	// The instance's explicit broadcast type suppresses the fallback on
	// ge-0-0-1.50 (the other p2p unit, ge-0-0-3.60, legitimately keeps its
	// generated line — suppression is per interface, not global).
	if strings.Contains(rendered, "interface ge-0-0-1.50\n ip ospf network point-to-point") {
		t.Errorf("VRF instance OSPF explicit network-type did not suppress the generated point-to-point line on ge-0-0-1.50:\n%s", rendered)
	}
	if n := strings.Count(rendered, " ip ospf network point-to-point\n"); n != 1 {
		t.Errorf("point-to-point lines = %d, want 1 (only the unsuppressed ge-0-0-3.60):\n%s", n, rendered)
	}
	if !strings.Contains(rendered, " ip ospf network broadcast\n") {
		t.Errorf("instance OSPF explicit network-type not rendered:\n%s", rendered)
	}
}
