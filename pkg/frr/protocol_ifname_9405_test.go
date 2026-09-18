package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9405. The FRR renderer wrote routing-protocol interface references into the
// managed section VERBATIM. The compiled value is the AUTHORED Junos reference
// (`ge-0/0/1.0`), Linux dev_valid_name() forbids `/`, so `interface ge-0/0/1.0`
// could never bind a netdev and no OSPF / OSPFv3 / IS-IS / RIP adjacency ever
// formed — on a commit that all four config channels ACCEPT with no warning.
//
// These cells assert the RENDERED OPERAND, not that a resolver was called: the
// operand is the whole contract with FRR, and a resolver invoked whose result
// is discarded would satisfy any call-count assertion.

// cfg9405 builds a config whose interfaces exercise the three resolution arms
// the protocol operand needs: unit-0 collapse, the RETH->local-member map, and
// the `.<vlan-id>` arm (#5107 — a unit NUMBERED 80 carrying `vlan-id 180` is
// the netdev `<member>.180`, and a resolver missing that arm names the wrong
// VLAN while looking perfectly plausible).
func cfg9405() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {
			Name:  "ge-0/0/1",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"ge-0/0/2": {
			Name:            "ge-0/0/2",
			RedundantParent: "reth0",
			Units:           map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
		"reth0": {
			Name: "reth0",
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0},
				80: {Number: 80, VlanID: 180},
			},
		},
	}
	return cfg
}

func render9405(t *testing.T, fc *FullConfig) string {
	t.Helper()
	m := &Manager{}
	return m.buildManagedSection(fc)
}

func TestProtocolInterfaceOperandsResolveToKernelNames9405(t *testing.T) {
	cfg := cfg9405()

	cases := []struct {
		name    string
		build   func(fc *FullConfig)
		want    []string
		notWant []string
	}{
		{
			name: "ospf unit-0 collapse",
			build: func(fc *FullConfig) {
				fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
					ID:         "0.0.0.0",
					Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0"}},
				}}}
			},
			want:    []string{"interface ge-0-0-1\n", " ip ospf area 0.0.0.0\n"},
			notWant: []string{"ge-0/0/1"},
		},
		{
			name: "ospf passive operand under router ospf",
			build: func(fc *FullConfig) {
				fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
					ID:         "0.0.0.0",
					Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0", Passive: true}},
				}}}
			},
			want:    []string{" passive-interface ge-0-0-1\n"},
			notWant: []string{"passive-interface ge-0/0/1.0"},
		},
		{
			name: "ospf no-passive operand under passive-default",
			build: func(fc *FullConfig) {
				fc.OSPF = &config.OSPFConfig{
					PassiveDefault: true,
					Areas: []*config.OSPFArea{{
						ID:         "0.0.0.0",
						Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0", NoPassive: true}},
					}},
				}
			},
			want:    []string{" no passive-interface ge-0-0-1\n"},
			notWant: []string{"no passive-interface ge-0/0/1.0"},
		},
		{
			name: "ospfv3 area activation and interface block",
			build: func(fc *FullConfig) {
				fc.OSPFv3 = &config.OSPFv3Config{Areas: []*config.OSPFv3Area{{
					ID:         "0.0.0.0",
					Interfaces: []*config.OSPFv3Interface{{Name: "ge-0/0/1.0", Cost: 10}},
				}}}
			},
			want: []string{
				"interface ge-0-0-1\n ipv6 ospf6 area 0.0.0.0\n ipv6 ospf6 cost 10\n",
			},
			notWant: []string{"ge-0/0/1"},
		},
		{
			name: "isis interface block",
			build: func(fc *FullConfig) {
				fc.ISIS = &config.ISISConfig{
					NET:        "49.0001.0100.0000.0001.00",
					Interfaces: []*config.ISISInterface{{Name: "ge-0/0/1.0"}},
				}
			},
			want:    []string{"interface ge-0-0-1\n ip router isis xpf\n"},
			notWant: []string{"ge-0/0/1"},
		},
		{
			name: "rip network and passive operands",
			build: func(fc *FullConfig) {
				fc.RIP = &config.RIPConfig{
					Interfaces: []string{"ge-0/0/1.0"},
					Passive:    []string{"reth0.0"},
				}
			},
			want:    []string{" network ge-0-0-1\n", " passive-interface ge-0-0-2\n"},
			notWant: []string{"ge-0/0/1.0", "reth0"},
		},
		{
			name: "reth reference resolves to the local physical member",
			build: func(fc *FullConfig) {
				fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
					ID:         "0.0.0.0",
					Interfaces: []*config.OSPFInterface{{Name: "reth0.0"}},
				}}}
			},
			want:    []string{"interface ge-0-0-2\n"},
			notWant: []string{"reth0"},
		},
		{
			name: "tagged unit resolves to the VLAN-ID device, not the unit number",
			build: func(fc *FullConfig) {
				fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
					ID:         "0.0.0.0",
					Interfaces: []*config.OSPFInterface{{Name: "reth0.80"}},
				}}}
			},
			want:    []string{"interface ge-0-0-2.180\n"},
			notWant: []string{"ge-0-0-2.80", "reth0.80"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{IfNameResolver: cfg.ResolveKernelIfName}
			tc.build(fc)
			got := render9405(t, fc)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("rendered managed section missing %q:\n%s", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("rendered managed section still carries the unresolved operand %q "+
						"— Linux dev_valid_name() forbids '/' and a unit suffix is not a device, "+
						"so this stanza binds nothing (#9405):\n%s", nw, got)
				}
			}
		})
	}
}

// TestForwardingInstanceProtocolOperandsResolve9405: the per-instance render
// path is a SECOND call site, not the same one. A fix applied only to the
// global block leaves every routing-instance protocol stanza raw.
func TestForwardingInstanceProtocolOperandsResolve9405(t *testing.T) {
	cfg := cfg9405()
	fc := &FullConfig{IfNameResolver: cfg.ResolveKernelIfName}
	fc.Instances = []InstanceConfig{{
		Name:    "ISP-B",
		VRFName: "vrf-ISP-B",
		OSPF: &config.OSPFConfig{Areas: []*config.OSPFArea{{
			ID:         "0.0.0.0",
			Interfaces: []*config.OSPFInterface{{Name: "ge-0/0/1.0"}},
		}}},
	}}
	got := render9405(t, fc)
	if !strings.Contains(got, "interface ge-0-0-1\n") {
		t.Fatalf("per-instance protocol operand not resolved:\n%s", got)
	}
	if strings.Contains(got, "ge-0/0/1") {
		t.Fatalf("per-instance protocol operand still raw:\n%s", got)
	}
}

// TestUnrenderableProtocolOperandIsDropped9405: the token belt. The schema
// leaf is free-form, so a whitespace- or newline-bearing reference commits
// clean on all four channels; rendered raw it splits `interface <name>` into
// extra operands, or appends an attacker-chosen statement outright. Same class
// as #9050. Dropping is the right granularity: one malformed line fails the
// WHOLE frr-reload (#1880/#2223), taking down every protocol.
func TestUnrenderableProtocolOperandIsDropped9405(t *testing.T) {
	cfg := cfg9405()
	for _, bad := range []string{"ge-0/0/1.0 zzz", "ge-0/0/1.0\n router bgp 65000", "ge-0/0/1.0\tx"} {
		fc := &FullConfig{IfNameResolver: cfg.ResolveKernelIfName}
		fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
			ID:         "0.0.0.0",
			Interfaces: []*config.OSPFInterface{{Name: bad}},
		}}}
		got := render9405(t, fc)
		if strings.Contains(got, "zzz") || strings.Contains(got, "router bgp") ||
			strings.Contains(got, "\tx") {
			t.Errorf("multi-token operand %q reached the managed section:\n%s", bad, got)
		}
		// Positive control in the same run: the surrounding stanza still
		// renders, so the drop is scoped to the bad operand and this cell is
		// not passing because nothing rendered at all.
		if !strings.Contains(got, "router ospf\n") {
			t.Errorf("operand %q: the OSPF stanza itself vanished, so the drop is "+
				"not scoped:\n%s", bad, got)
		}
	}
}

// TestNilIfNameResolverIsIdentity9405 pins the compatibility contract: a
// FullConfig built without a *config.Config in hand renders exactly what it
// rendered before #9405. Without this, the resolver becomes a hidden required
// field and every direct generateProtocols caller silently changes shape.
func TestNilIfNameResolverIsIdentity9405(t *testing.T) {
	fc := &FullConfig{}
	fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
		ID:         "0.0.0.0",
		Interfaces: []*config.OSPFInterface{{Name: "ge-0-0-1"}},
	}}}
	got := render9405(t, fc)
	if !strings.Contains(got, "interface ge-0-0-1\n") {
		t.Fatalf("nil resolver must be identity:\n%s", got)
	}
}

// TestOSPFNetworkTypeSuppressionMatchesKernelName9405: resolving the protocol
// operand creates a collision the raw spelling hid. generateInterfaceSettings
// emits `ip ospf network point-to-point` for a p2p unit unless the OSPF config
// already sets an explicit network-type — and it keys that suppression on the
// OSPF interface NAME while InterfacePointToPoint is keyed by KERNEL name. With
// the raw slash spelling the two could never match, so the suppression was
// inert; once both name ge-0-0-1 it must actually fire, or one interface gets
// two conflicting `ip ospf network` lines.
func TestOSPFNetworkTypeSuppressionMatchesKernelName9405(t *testing.T) {
	cfg := cfg9405()
	fc := &FullConfig{
		IfNameResolver:        cfg.ResolveKernelIfName,
		InterfacePointToPoint: map[string]bool{"ge-0-0-1": true},
	}
	fc.OSPF = &config.OSPFConfig{Areas: []*config.OSPFArea{{
		ID: "0.0.0.0",
		Interfaces: []*config.OSPFInterface{
			{Name: "ge-0/0/1.0", NetworkType: "broadcast"},
		},
	}}}
	got := render9405(t, fc)
	if n := strings.Count(got, "ip ospf network"); n != 1 {
		t.Fatalf("`ip ospf network` rendered %d times, want exactly the operator's "+
			"explicit one:\n%s", n, got)
	}
	if !strings.Contains(got, " ip ospf network broadcast\n") {
		t.Fatalf("the operator's explicit network-type lost:\n%s", got)
	}
}
