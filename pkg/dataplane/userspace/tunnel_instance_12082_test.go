package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestTunnelStanzaInstanceScopesRowAndOuterTransport12082(t *testing.T) {
	cfg, err := config.CompileConfig(treeFromSet6722(t, []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
	}))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}

	previous := buildLinkSnapshot
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 362, 1500, "", nil
	}
	t.Cleanup(func() { buildLinkSnapshot = previous })

	snaps := BuildInterfaceSnapshots(cfg)
	row := snapshotByName9132(t, snaps, "gr-0/0/0.0")
	if row.RoutingInstance != "blue" {
		t.Fatalf("tunnel interface row routing-instance = %q, want blue", row.RoutingInstance)
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, snaps)
	if len(endpoints) != 1 {
		t.Fatalf("tunnel endpoints = %d, want 1", len(endpoints))
	}
	if endpoints[0].TransportTable != "blue.inet.0" {
		t.Fatalf("outer transport table = %q, want blue.inet.0", endpoints[0].TransportTable)
	}
}

func TestZoneHostInboundStanzaTunnelUsesVRFMasterAndScope12082(t *testing.T) {
	cfg, err := config.CompileConfig(treeFromSet6722(t, []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set routing-instances blue instance-type virtual-router",
		"set security zones security-zone untrust interfaces gr-0/0/0.0",
		"set security zones security-zone untrust host-inbound-traffic system-services ping",
	}))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}

	previous := buildLinkSnapshot
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "gr-0-0-0" {
			return 362, 1500, "", nil
		}
		return 0, 0, "", nil
	}
	t.Cleanup(func() { buildLinkSnapshot = previous })

	views := BuildZoneHostInboundViews(cfg)
	for _, view := range views {
		if view.Zone != "untrust" {
			continue
		}
		if len(view.IngressNetdevs) != 1 || view.IngressNetdevs[0] != "vrf-blue" {
			t.Fatalf("stanza-tunnel host-inbound ingress = %v, want [vrf-blue]", view.IngressNetdevs)
		}
		if len(view.IngressVRFScopes) != 1 ||
			view.IngressVRFScopes[0].Master != "vrf-blue" ||
			len(view.IngressVRFScopes[0].Slaves) != 1 ||
			view.IngressVRFScopes[0].Slaves[0] != "gr-0-0-0" {
			t.Fatalf("stanza-tunnel host-inbound VRF scopes = %+v, want vrf-blue -> [gr-0-0-0]",
				view.IngressVRFScopes)
		}
		return
	}
	t.Fatalf("host-inbound views omitted untrust zone: %+v", views)
}

func TestFabricZoneTunnelOwnershipMatchesRuntimeDomains11061(t *testing.T) {
	cases := []struct {
		name       string
		lines      []string
		wantStrict bool
		want       map[string]string
		ifindexes  map[string]int
	}{
		{
			name: "A1-stanza-must-not-fail-open",
			lines: []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
				"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
				"set routing-instances blue instance-type virtual-router",
				"set security zones security-zone trust interfaces gr-0/0/0.0",
				"set security zones security-zone trust interfaces ge-0/0/1.0",
			},
			wantStrict: false,
			want:       map[string]string{"gr-0/0/0.0": "blue", "ge-0/0/1.0": ""},
			ifindexes:  map[string]int{"gr-0/0/0.0": 362, "ge-0/0/1.0": 363},
		},
		{
			name: "A2-same-stanza-and-list-owner",
			lines: []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/2.0",
				"set security zones security-zone vpn interfaces gr-0/0/0.0",
				"set security zones security-zone vpn interfaces ge-0/0/2.0",
			},
			wantStrict: true,
			want:       map[string]string{"gr-0/0/0.0": "blue", "ge-0/0/2.0": "blue"},
			ifindexes:  map[string]int{"gr-0/0/0.0": 362, "ge-0/0/2.0": 364},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := treeFromSet6722(t, tc.lines)
			cfg, err := config.CompileConfig(tree)
			if tc.wantStrict && err != nil {
				t.Fatalf("strict compile rejected gate/runtime-consistent shape: %v", err)
			}
			if !tc.wantStrict {
				if err == nil {
					t.Fatal("strict compile accepted runtime-ambiguous fabric-zone membership")
				}
				cfg, err = config.CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("tolerant compile: %v", err)
				}
			}

			previous := buildLinkSnapshot
			buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
				switch name {
				case "gr-0-0-0":
					return 362, 1500, "", nil
				case "ge-0-0-1":
					return 363, 1500, "", nil
				case "ge-0-0-2":
					return 364, 1500, "", nil
				default:
					return 0, 0, "", nil
				}
			}
			t.Cleanup(func() { buildLinkSnapshot = previous })

			snaps := BuildInterfaceSnapshots(cfg)
			for name, wantRI := range tc.want {
				row := snapshotByName9132(t, snaps, name)
				wantDomain := uint32(0)
				if wantRI != "" {
					wantDomain = routingInstanceDomain(wantRI)
				}
				if row.Ifindex != tc.ifindexes[name] {
					t.Errorf("snapshot %s ifindex = %d, want stubbed ifindex %d",
						name, row.Ifindex, tc.ifindexes[name])
				}
				if row.RoutingInstance != wantRI || row.RoutingDomain != wantDomain {
					t.Errorf("snapshot %s = (instance %q, domain %d), want (%q, %d)",
						name, row.RoutingInstance, row.RoutingDomain, wantRI, wantDomain)
				}
			}
		})
	}
}

func tunnelMembershipConfig12082(t *testing.T, lines []string) *config.Config {
	t.Helper()
	cfg, err := config.CompileConfig(treeFromSet6722(t, lines))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	return cfg
}

func TestTunnelDualClaimStanzaAndSiblingGuards11060G1(t *testing.T) {
	cfg := tunnelMembershipConfig12082(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.10.11.1/30",
		"set routing-instances blue instance-type virtual-router",
	})
	cfg.RoutingInstances = append(cfg.RoutingInstances, &config.RoutingInstanceConfig{
		Name: "red", InstanceType: "virtual-router", Interfaces: []string{"gr-0/0/0"},
	})
	if got := buildInterfaceRoutingInstances(cfg); len(got) != 0 {
		t.Fatalf("dual-claimed tunnel stanza/list rows = %v, want no owner", got)
	}
}

func TestTunnelDualClaimSiblingGuard11060G2(t *testing.T) {
	cfg := tunnelMembershipConfig12082(t, []string{
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.10.11.1/30",
	})
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "virtual-router", Interfaces: []string{"gr-0/0/0.0"}},
		{Name: "red", InstanceType: "virtual-router", Interfaces: []string{"gr-0/0/0.1"}},
	}
	if got := buildInterfaceRoutingInstances(cfg); len(got) != 0 {
		t.Fatalf("dual-claimed tunnel sibling rows = %v, want no owner", got)
	}
}

func TestTunnelStanzaActiveInstanceGuard11060G3(t *testing.T) {
	for _, tc := range []struct {
		name         string
		instance     string
		instanceType string
		define       bool
	}{
		{name: "forwarding-instance", instance: "fwd", instanceType: "forwarding", define: true},
		{name: "undefined-instance", instance: "nosuch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 tunnel routing-instance destination " + tc.instance,
				"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
			}
			if tc.define {
				lines = append(lines,
					"set routing-instances "+tc.instance+" instance-type "+tc.instanceType)
			}
			cfg := tunnelMembershipConfig12082(t, lines)
			if got := buildInterfaceRoutingInstances(cfg); len(got) != 0 {
				t.Fatalf("tunnel stanza rows for %q = %v, want no active owner", tc.instance, got)
			}
		})
	}
}
