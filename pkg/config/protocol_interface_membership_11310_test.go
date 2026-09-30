package config

import (
	"strings"
	"testing"
)

func buildProtocolMembershipTree11310(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func protocolMembershipInterface11310() string {
	return "set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24"
}

func TestProtocolInterfaceMembershipRejected11310(t *testing.T) {
	base := protocolMembershipInterface11310()
	cases := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "global protocol references RI-owned aliased device",
			lines: []string{
				base,
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.0 interface ge-0-0-1.0",
			},
			want: []string{"#11310", "protocols ospf interface", "ge-0-0-1.0", "blue"},
		},
		{
			name: "RI protocol references default-instance device",
			lines: []string{
				base,
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			},
			want: []string{"#11310", "no routing-instance owner", "default instance", "blue"},
		},
		{
			name: "RI protocol references another RI's device",
			lines: []string{
				base,
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/1.0",
				"set routing-instances red instance-type virtual-router",
				"set routing-instances red protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			},
			want: []string{"#11310", "owned by routing-instance \"blue\"", "protocol instance \"red\""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildProtocolMembershipTree11310(t, tc.lines...))
			if err == nil {
				t.Fatal("strict compile accepted a protocol interface reference with mismatched instance ownership")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestProtocolInterfaceMembershipWarnsOnTolerantCompile11310(t *testing.T) {
	cfg, err := CompileConfigLenient(buildProtocolMembershipTree11310(t,
		protocolMembershipInterface11310(),
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/1.0",
		"set protocols ospf area 0.0.0.0 interface ge-0-0-1.0",
	))
	if err != nil {
		t.Fatalf("tolerant compile rejected a legacy protocol membership mismatch: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "protocol interface membership") &&
			strings.Contains(warning, "#11310") && strings.Contains(warning, "blue") {
			return
		}
	}
	t.Fatalf("tolerant compile omitted the #11310 ownership warning: %v", cfg.Warnings)
}

func TestProtocolInterfaceMembershipTunnelWarnsOnTolerantCompile11310(t *testing.T) {
	lines := append(interfaceTunnelMembershipLines11310(),
		"set protocols ospf area 0.0.0.0 interface gr-0/0/0")
	cfg, err := CompileConfigLenient(buildProtocolMembershipTree11310(t, lines...))
	if err != nil {
		t.Fatalf("tolerant compile rejected a legacy tunnel ownership mismatch: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "protocol interface membership") &&
			strings.Contains(warning, "#11310") &&
			strings.Contains(warning, "gr-0/0/0") {
			return
		}
	}
	t.Fatalf("tolerant compile omitted the tunnel ownership warning: %v", cfg.Warnings)
}

func TestProtocolInterfaceMembershipControls11310(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "global protocol on default-instance device",
			lines: []string{
				protocolMembershipInterface11310(),
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			},
		},
		{
			name: "RI protocol on same RI-owned device",
			lines: []string{
				protocolMembershipInterface11310(),
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/1.0",
				"set routing-instances blue protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
			},
		},
		{
			name: "global interface all remains outside membership checks",
			lines: []string{
				protocolMembershipInterface11310(),
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.0 interface all",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildProtocolMembershipTree11310(t, tc.lines...)); err != nil {
				t.Fatalf("valid protocol interface ownership was rejected: %v", err)
			}
		})
	}
}

func TestProtocolInterfaceMembershipCoversProtocolInterfaceLists11310(t *testing.T) {
	const ref = "ge-0/0/1.0"
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "owner", Interfaces: []string{ref}},
			{
				Name:   "scope",
				OSPF:   &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: ref}}}}},
				OSPFv3: &OSPFv3Config{Areas: []*OSPFv3Area{{Interfaces: []*OSPFv3Interface{{Name: ref}}}}},
				RIP:    &RIPConfig{Interfaces: []string{ref}, Passive: []string{ref}},
				ISIS:   &ISISConfig{Interfaces: []*ISISInterface{{Name: ref}}},
			},
		},
	}
	mismatches := protocolInterfaceMembershipMismatches11310(cfg)
	if len(mismatches) != 5 {
		t.Fatalf("mismatches = %v, want OSPF, OSPFv3, RIP neighbor, RIP passive-interface, and IS-IS refs", mismatches)
	}
	joined := strings.Join(mismatches, "\n")
	for _, proto := range []string{"ospf", "ospf3", "rip", "isis"} {
		if !strings.Contains(joined, "scope protocols "+proto+" interface "+ref) {
			t.Errorf("mismatch list omitted %s interface ref: %v", proto, mismatches)
		}
	}
	if count := strings.Count(joined, "scope protocols rip interface "+ref); count != 2 {
		t.Errorf("RIP interface and passive-interface refs produced %d diagnostics, want 2: %v", count, mismatches)
	}
}

func TestProtocolInterfaceMembershipLeavesUndeclaredRefsTo9405_11310(t *testing.T) {
	const ref = "ge-0/0/9.0"
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Protocols: ProtocolsConfig{
			OSPF: &OSPFConfig{Areas: []*OSPFArea{{Interfaces: []*OSPFInterface{{Name: ref}}}}},
		},
		RoutingInstances: []*RoutingInstanceConfig{{
			Name: "blue", Interfaces: []string{ref},
		}},
	}
	if got := protocolInterfaceMembershipMismatches11310(cfg); len(got) != 0 {
		t.Fatalf("membership gate diagnosed undeclared #9405 ref %q: %v", ref, got)
	}
	if got := validateProtocolInterfaceRefWarnings(cfg); len(got) == 0 {
		t.Fatalf("undeclared ref %q did not remain visible to #9405", ref)
	}
}

func TestRoutingInstanceMemberDeviceOwnersForRefs11310(t *testing.T) {
	unit := func(name string) *InterfaceConfig {
		return &InterfaceConfig{Name: name, Units: map[int]*InterfaceUnit{0: {Number: 0}}}
	}
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/1": unit("ge-0/0/1"),
			"ge-0/0/2": unit("ge-0/0/2"),
			"ge-0/0/3": unit("ge-0/0/3"),
			"ge-0/0/4": unit("ge-0/0/4"),
		}},
		RoutingInstances: []*RoutingInstanceConfig{
			{Name: "first", Interfaces: []string{"ge-0/0/1.0"}},
			{Name: "second", Interfaces: []string{"ge-0-0-1.0"}},
			{Name: "forwarding", InstanceType: "forwarding", Interfaces: []string{"ge-0/0/2.0"}},
			{Name: "mgmt", Interfaces: []string{"ge-0/0/3.0"}},
			{Name: "", Interfaces: []string{"ge-0/0/4.0"}},
		},
	}
	deviceOwners := RoutingInstanceMemberLinuxNameOwners(cfg)
	if got := deviceOwners["ge-0-0-1"]; got != "first" {
		t.Errorf("duplicate device owner = %q, want first declared owner", got)
	}
	if got := deviceOwners["ge-0-0-2"]; got != "forwarding" {
		t.Errorf("forwarding member owner = %q, want forwarding", got)
	}
	for _, device := range []string{"ge-0-0-3", "ge-0-0-4", ""} {
		if _, found := deviceOwners[device]; found {
			t.Errorf("reserved/empty RI claimed owner entry %q: %v", device, deviceOwners)
		}
	}
	refOwners := RoutingInstanceMemberDeviceOwnersForRefs(cfg, []string{
		"ge-0/0/1.0", "ge-0-0-1.0", "ge-0/0/2.0", "ge-0/0/9.0",
	})
	for ref, want := range map[string]string{
		"ge-0/0/1.0": "first",
		"ge-0-0-1.0": "first",
		"ge-0/0/2.0": "forwarding",
		"ge-0/0/9.0": "",
	} {
		if got := refOwners[ref]; got != want {
			t.Errorf("owner of %q = %q, want %q", ref, got, want)
		}
	}
	vlanCfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"ge-0/0/5": {
				Name:  "ge-0/0/5",
				Units: map[int]*InterfaceUnit{0: {Number: 0, VlanID: 100}},
			},
		}},
		RoutingInstances: []*RoutingInstanceConfig{{
			Name: "vlan-blue", Interfaces: []string{"ge-0/0/5.0"},
		}},
	}
	vlanRefOwners := RoutingInstanceMemberDeviceOwnersForRefs(vlanCfg, []string{
		"ge-0/0/5.0", "ge-0/0/5.999", "ge-0/0/5.100",
	})
	for ref, want := range map[string]string{
		"ge-0/0/5.0":   "vlan-blue",
		"ge-0/0/5.999": "",
		"ge-0/0/5.100": "",
	} {
		if got := vlanRefOwners[ref]; got != want {
			t.Errorf("owner of %q = %q, want %q", ref, got, want)
		}
	}
	if got := RoutingInstanceMemberDeviceOwnersForRefs(vlanCfg, []string{"all"})["all"]; got != "" {
		t.Errorf("owner of interface all = %q, want empty", got)
	}
	if got := RoutingInstanceMemberLinuxNameOwners(nil); len(got) != 0 {
		t.Errorf("nil config owners = %v, want empty map", got)
	}
	if got := RoutingInstanceMemberDeviceOwnersForRefs(nil, []string{"ge-0/0/1.0"}); len(got) != 0 {
		t.Errorf("nil config ref owners = %v, want empty map", got)
	}
}

func interfaceTunnelMembershipLines11310() []string {
	return []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
	}
}

func unitTunnelMembershipLines11310() []string {
	return []string{
		"set interfaces gr-0/0/1 unit 1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 unit 1 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 unit 1 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
	}
}

func TestProtocolInterfaceMembershipTunnelStanzaClaims11310(t *testing.T) {
	interfaceLines := interfaceTunnelMembershipLines11310()
	unitLines := unitTunnelMembershipLines11310()
	cases := []struct {
		name     string
		lines    []string
		wantErr  bool
		wantText []string
	}{
		{
			name:     "global protocol rejects interface-level tunnel owner",
			lines:    append(interfaceLines, "set protocols ospf area 0.0.0.0 interface gr-0/0/0"),
			wantErr:  true,
			wantText: []string{"#11310", "gr-0/0/0", "owned by routing-instance \"blue\""},
		},
		{
			name:  "same RI accepts interface-level tunnel owner without member list",
			lines: append(interfaceTunnelMembershipLines11310(), "set routing-instances blue protocols ospf area 0.0.0.0 interface gr-0/0/0"),
		},
		{
			name: "other RI rejects interface-level tunnel owner",
			lines: append(interfaceTunnelMembershipLines11310(),
				"set routing-instances red instance-type virtual-router",
				"set routing-instances red protocols ospf area 0.0.0.0 interface gr-0/0/0"),
			wantErr:  true,
			wantText: []string{"#11310", "owned by routing-instance \"blue\"", "protocol instance \"red\""},
		},
		{
			name:  "same RI accepts unit-level tunnel owner without member list",
			lines: append(unitLines, "set routing-instances blue protocols ospf area 0.0.0.0 interface gr-0/0/1.1"),
		},
		{
			name: "other RI rejects unit-level tunnel owner",
			lines: append(unitTunnelMembershipLines11310(),
				"set routing-instances red instance-type virtual-router",
				"set routing-instances red protocols ospf area 0.0.0.0 interface gr-0/0/1.1"),
			wantErr:  true,
			wantText: []string{"#11310", "gr-0/0/1.1", "owned by routing-instance \"blue\"", "protocol instance \"red\""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildProtocolMembershipTree11310(t, tc.lines...))
			if err == nil && tc.wantErr {
				t.Fatal("strict compile accepted a protocol reference with a mismatched tunnel owner")
			}
			if err != nil && !tc.wantErr {
				t.Fatalf("strict compile rejected a same-RI tunnel protocol reference with no interface list: %v", err)
			}
			for _, want := range tc.wantText {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("strict error %v does not contain %q", err, want)
				}
			}
		})
	}
}

func TestProtocolMembershipGatePreservesDualClaimFirstError11310(t *testing.T) {
	lines := append(interfaceTunnelMembershipLines11310(),
		"set routing-instances red instance-type virtual-router",
		"set routing-instances red interface gr-0/0/0",
		"set protocols ospf area 0.0.0.0 interface gr-0/0/0",
	)
	_, err := CompileConfig(buildProtocolMembershipTree11310(t, lines...))
	if err == nil {
		t.Fatal("strict compile accepted conflicting tunnel and member ownership")
	}
	if !strings.Contains(err.Error(), "#11060") {
		t.Errorf("dual-claim gate did not preserve its earlier error: %v", err)
	}
	if strings.Contains(err.Error(), "#11310") {
		t.Errorf("protocol membership gate preempted the #11060 dual-claim error: %v", err)
	}
}
