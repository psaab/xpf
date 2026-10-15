package userspace

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A bare security-zone member must name the materialized logical unit even if
// the IPsec bind-interface is the only stanza naming the tunnel. This covers
// both Linux device spellings: st0 and st0.0 are different netdev names for
// the same st0.0 logical unit.
func TestBareZoneBindOnlyTunnelHostInbound13100(t *testing.T) {
	for _, bind := range []string{"st0", "st0.0"} {
		for _, override := range []bool{false, true} {
			name := bind + "/zone-only"
			if override {
				name = bind + "/unit-override"
			}
			t.Run(name, func(t *testing.T) {
				lines := []string{
					"set security ipsec vpn v bind-interface " + bind,
					"set security zones security-zone vpn interfaces st0",
					"set security zones security-zone vpn host-inbound-traffic system-services all",
				}
				wantServices := []string{"all"}
				if override {
					lines = append(lines, "set security zones security-zone vpn interfaces st0.0 host-inbound-traffic system-services ping")
					wantServices = []string{"ping"}
				}
				cfg := compileForTest5619(t, lines...)
				if len(cfg.Interfaces.Interfaces) != 0 {
					t.Fatalf("fixture is not bind-interface-only: %+v", cfg.Interfaces.Interfaces)
				}
				previous := buildLinkSnapshot
				t.Cleanup(func() { buildLinkSnapshot = previous })
				buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
					if name == bind {
						return 42, 1400, "", nil // unnumbered: ingress must still be claimed
					}
					return 0, 0, "", nil
				}

				rows := buildInterfaceSnapshots(cfg)
				row, ok := rowByName7949(rows, "st0.0")
				if !ok || len(rows) != 1 {
					t.Fatalf("bare zone + bind %q must produce one st0.0 row, got %+v", bind, rows)
				}
				if !row.IsUnit || row.Zone != "vpn" || row.EgressZone != "vpn" || row.LinuxName != bind || row.Ifindex != 42 || !row.SecureTunnel {
					t.Errorf("bind %q produced inert/misidentified logical unit: %+v", bind, row)
				}
				if row.HostInboundConfigured != override || (override && !reflect.DeepEqual(row.HostInboundSystemServices, wantServices)) {
					t.Errorf("bind %q Rust host-inbound override = %v (configured %v), want %v (configured %v)", bind, row.HostInboundSystemServices, row.HostInboundConfigured, wantServices, override)
				}
				var ingress []ZoneHostInboundView
				for _, view := range BuildZoneHostInboundViewsFromSnapshots(cfg, rows) {
					if len(view.IngressNetdevs) != 0 {
						ingress = append(ingress, view)
					}
				}
				if len(ingress) != 1 || ingress[0].Zone != "vpn" ||
					!reflect.DeepEqual(ingress[0].IngressNetdevs, []string{bind}) ||
					!reflect.DeepEqual(ingress[0].SystemServices, wantServices) {
					t.Errorf("bind %q nft ingress override = %+v, want one scoped %v view", bind, ingress, wantServices)
				}
			})
		}
	}
}

func TestBareZoneBindOnlyTunnelInheritsPhysicalOverride13100(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0",
		"set security zones security-zone vpn host-inbound-traffic system-services all",
		"set security zones security-zone vpn interfaces st0 host-inbound-traffic system-services ssh",
		"set security zones security-zone vpn interfaces st0.0 host-inbound-traffic system-services ping",
	)
	got := config.ResolveInterfaceHostInbound(cfg)["st0.0"]
	if got == nil || !reflect.DeepEqual(got.SystemServices, []string{"ssh", "ping"}) {
		t.Fatalf("logical unit override = %+v, want inherited ssh plus unit ping", got)
	}
}

func TestBareZoneBoundTunnelConflictFailsClosed13100(t *testing.T) {
	lines := []string{
		"set security ipsec vpn v bind-interface st0.0",
		"set security zones security-zone vpn interfaces st0",
		"set security zones security-zone other interfaces st0.0",
	}
	// Strict commit rejects two zones for the same implicit unit. Tolerant
	// loading keeps running, but never elects a sorted-name winner for st0.0.
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "assigned to security zones") {
		t.Fatalf("strict commit must reject conflicting implicit unit ownership, got %v", err)
	}
	cfg := lenientConfig7949(t, lines...)
	if _, quarantined := config.QuarantinedZoneInterfaceKeys(cfg)["st0.0"]; !quarantined {
		t.Fatal("tolerant loading failed to quarantine the disputed logical unit")
	}
	for _, row := range buildInterfaceSnapshots(cfg) {
		if row.LinuxName == "st0.0" && row.Zone != "" {
			t.Fatalf("tolerant conflict elected a tunnel-zone winner: %+v", row)
		}
	}
}
