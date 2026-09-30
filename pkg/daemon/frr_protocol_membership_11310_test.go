package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
)

func protocolMembershipConfig11310() *config.Config {
	interfaces := make(map[string]*config.InterfaceConfig, 3)
	for _, name := range []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"} {
		interfaces[name] = &config.InterfaceConfig{
			Name:  name,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		}
	}
	ospf := func(area string, refs ...string) *config.OSPFConfig {
		areaCfg := &config.OSPFArea{ID: area}
		for _, ref := range refs {
			areaCfg.Interfaces = append(areaCfg.Interfaces, &config.OSPFInterface{Name: ref})
		}
		return &config.OSPFConfig{Areas: []*config.OSPFArea{areaCfg}}
	}
	ospfv3 := func(area string, refs ...string) *config.OSPFv3Config {
		areaCfg := &config.OSPFv3Area{ID: area}
		for _, ref := range refs {
			areaCfg.Interfaces = append(areaCfg.Interfaces, &config.OSPFv3Interface{Name: ref})
		}
		return &config.OSPFv3Config{Areas: []*config.OSPFv3Area{areaCfg}}
	}
	isis := func(refs ...string) *config.ISISConfig {
		isisCfg := &config.ISISConfig{}
		for _, ref := range refs {
			isisCfg.Interfaces = append(isisCfg.Interfaces, &config.ISISInterface{Name: ref})
		}
		return isisCfg
	}
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: interfaces},
		Protocols: config.ProtocolsConfig{
			OSPF:   ospf("0.0.0.0", "ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
			OSPFv3: ospfv3("0.0.0.0", "ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
			RIP: &config.RIPConfig{
				Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"},
				Passive:    []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"},
			},
			ISIS: isis("ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{
				Name:         "blue",
				InstanceType: "virtual-router",
				Interfaces:   []string{"ge-0/0/1.0"},
				OSPF:         ospf("0.0.0.1", "ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
				OSPFv3:       ospfv3("0.0.0.1", "ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
				RIP: &config.RIPConfig{
					Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"},
					Passive:    []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"},
				},
				ISIS: isis("ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"),
			},
			{
				Name:         "red",
				InstanceType: "virtual-router",
				Interfaces:   []string{"ge-0/0/2.0"},
			},
		},
	}
}

func TestAssemblerFiltersProtocolInterfacesByRoutingInstance11310(t *testing.T) {
	cfg := protocolMembershipConfig11310()
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)

	assertNames := func(label string, got []string, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s interfaces = %v, want %v", label, got, want)
		}
	}
	ospfNames := func(areas []*config.OSPFArea) []string {
		var names []string
		for _, area := range areas {
			for _, iface := range area.Interfaces {
				names = append(names, iface.Name)
			}
		}
		return names
	}
	ospfv3Names := func(areas []*config.OSPFv3Area) []string {
		var names []string
		for _, area := range areas {
			for _, iface := range area.Interfaces {
				names = append(names, iface.Name)
			}
		}
		return names
	}
	isisNames := func(isis *config.ISISConfig) []string {
		var names []string
		for _, iface := range isis.Interfaces {
			names = append(names, iface.Name)
		}
		return names
	}

	assertNames("global OSPF", ospfNames(fc.OSPF.Areas), []string{"ge-0/0/0.0"})
	assertNames("global OSPFv3", ospfv3Names(fc.OSPFv3.Areas), []string{"ge-0/0/0.0"})
	assertNames("global RIP", fc.RIP.Interfaces, []string{"ge-0/0/0.0"})
	assertNames("global passive RIP", fc.RIP.Passive, []string{"ge-0/0/0.0"})
	assertNames("global IS-IS", isisNames(fc.ISIS), []string{"ge-0/0/0.0"})

	if len(fc.Instances) != 2 {
		t.Fatalf("instances = %d, want blue and red", len(fc.Instances))
	}
	blue := fc.Instances[0]
	assertNames("blue OSPF", ospfNames(blue.OSPF.Areas), []string{"ge-0/0/1.0"})
	assertNames("blue OSPFv3", ospfv3Names(blue.OSPFv3.Areas), []string{"ge-0/0/1.0"})
	assertNames("blue RIP", blue.RIP.Interfaces, []string{"ge-0/0/1.0"})
	assertNames("blue passive RIP", blue.RIP.Passive, []string{"ge-0/0/1.0"})
	assertNames("blue IS-IS", isisNames(blue.ISIS), []string{"ge-0/0/1.0"})

	// Assembly filters copies: the active config remains available for show and
	// subsequent config processing exactly as authored.
	if got := len(cfg.Protocols.OSPF.Areas[0].Interfaces); got != 3 {
		t.Errorf("active global OSPF interfaces = %d, want all 3 authored references", got)
	}
	if got := len(cfg.RoutingInstances[0].OSPF.Areas[0].Interfaces); got != 3 {
		t.Errorf("active blue OSPF interfaces = %d, want all 3 authored references", got)
	}
}

func TestRenderedProtocolMembership11310(t *testing.T) {
	fc := (&Daemon{}).assembleFRRConfig(protocolMembershipConfig11310(), nil)
	got := renderFRRConfig11310(t, fc)
	for _, tc := range []struct {
		line string
		want int
	}{
		{"router ospf\n", 1},
		{"router ospf vrf vrf-blue\n", 1},
		{"router ospf6\n", 1},
		{"router ospf6 vrf vrf-blue\n", 1},
		{" ip ospf area 0.0.0.0\n", 1},
		{" ip ospf area 0.0.0.1\n", 1},
		{" ip ospf area 0.0.0.2\n", 0},
		{" ipv6 ospf6 area 0.0.0.0\n", 1},
		{" ipv6 ospf6 area 0.0.0.1\n", 1},
		{" ipv6 ospf6 area 0.0.0.2\n", 0},
		{" network ge-0-0-0\n", 1},
		{" network ge-0-0-1\n", 1},
		{" network ge-0-0-2\n", 0},
		{" passive-interface ge-0-0-0\n", 1},
		{" passive-interface ge-0-0-1\n", 1},
		{" passive-interface ge-0-0-2\n", 0},
		{" ip router isis xpf\n", 2},
		{" ipv6 router isis xpf\n", 2},
	} {
		if n := strings.Count(got, tc.line); n != tc.want {
			t.Errorf("%q rendered %d times, want %d:\n%s", tc.line, n, tc.want, got)
		}
	}
}
func TestTunnelProtocolMembershipUsesExplicitVRFOwner11310(t *testing.T) {
	const (
		interfaceRef = "gr-0/0/0.0"
		unitRef      = "ip-0/0/0.0"
	)
	ospf := func(area string, refs ...string) *config.OSPFConfig {
		areaCfg := &config.OSPFArea{ID: area}
		for _, ref := range refs {
			areaCfg.Interfaces = append(areaCfg.Interfaces, &config.OSPFInterface{Name: ref})
		}
		return &config.OSPFConfig{Areas: []*config.OSPFArea{areaCfg}}
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"gr-0/0/0": {
				Name: "gr-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0},
				},
				Tunnel: &config.TunnelConfig{
					Name:            "gr-0-0-0",
					Source:          "192.0.2.1",
					Destination:     "192.0.2.2",
					RoutingInstance: "blue",
				},
			},
			"ip-0/0/0": {
				Name: "ip-0/0/0",
				Units: map[int]*config.InterfaceUnit{
					0: {
						Number: 0,
						Tunnel: &config.TunnelConfig{
							Name:            "ip-0-0-0",
							Mode:            "gre",
							Source:          "192.0.2.3",
							Destination:     "192.0.2.4",
							RoutingInstance: "blue",
						},
					},
				},
			},
		}},
		Protocols: config.ProtocolsConfig{
			OSPF: ospf("0.0.0.0", interfaceRef, unitRef),
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{
				Name:         "blue",
				InstanceType: "virtual-router",
				OSPF:         ospf("0.0.0.1", interfaceRef, unitRef),
			},
			{
				Name:         "red",
				InstanceType: "virtual-router",
				OSPF:         ospf("0.0.0.2", interfaceRef, unitRef),
			},
		},
	}
	fc := (&Daemon{}).assembleFRRConfig(cfg, nil)
	if got := len(fc.OSPF.Areas[0].Interfaces); got != 0 {
		t.Errorf("global OSPF kept %d tunnel-owned references, want none", got)
	}
	if got := len(fc.Instances[0].OSPF.Areas[0].Interfaces); got != 2 {
		t.Errorf("blue OSPF kept %d explicit tunnel-owned references, want 2", got)
	}
	if got := len(fc.Instances[1].OSPF.Areas[0].Interfaces); got != 0 {
		t.Errorf("red OSPF kept %d blue tunnel-owned references, want none", got)
	}
	if got := len(cfg.Protocols.OSPF.Areas[0].Interfaces); got != 2 {
		t.Errorf("assembly mutated active global OSPF references: %d", got)
	}

	rendered := renderFRRConfig11310(t, fc)
	for _, tc := range []struct {
		line string
		want int
	}{
		{" ip ospf area 0.0.0.0\n", 0},
		{" ip ospf area 0.0.0.1\n", 2},
		{" ip ospf area 0.0.0.2\n", 0},
	} {
		if n := strings.Count(rendered, tc.line); n != tc.want {
			t.Errorf("%q rendered %d times, want %d:\n%s", tc.line, n, tc.want, rendered)
		}
	}
}

func renderFRRConfig11310(t *testing.T, fc *frr.FullConfig) string {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "frr.conf")
	if err := os.WriteFile(conf, []byte("frr version 10.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := frr.NewForTest(conf, &frr.RecordingExecutor{})
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("ApplyFull: %v", err)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
