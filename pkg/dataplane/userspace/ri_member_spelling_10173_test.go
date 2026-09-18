package userspace

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10173: the userspace FIB ignores cross-spelled unit-member aliases — the
// kernel VRF binds the right netdev (#10151) while the FIB keeps default
// scoping, the exact divergence #9815 closed, persisting on the default path.
//
// forEachRoutingInstanceInterfaceKey binds a unit member ONLY under its
// as-written spelling, but snapshot rows are keyed by DECLARED spelling
// (buildInterfaceSnapshots iterates cfg.Interfaces.Interfaces), so a
// cross-spelled member's key reaches no row: the connected prefix installs
// into inet.0 with RoutingInstance "" and domain 0. quarantinedInterfaceKeys
// misses the same way, folding a quarantined tenant's row into the default
// session domain instead of the sentinel.
//
// spellingCfg10173 mirrors spellingCfg9815 (daemon/routing): a vlan-tagging
// port with unit 0 on vlan 10 and unit 1 on vlan 50, plus an unclaimed
// control port so the default table is never vacuously empty. Addresses make
// the connected-prefix owning table observable end to end.
func spellingCfg10173(stanza, member string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		stanza: {
			Name:        stanza,
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 10, Addresses: []string{"192.168.10.1/24"}},
				1: {Number: 1, VlanID: 50, Addresses: []string{"192.168.50.1/24"}},
			},
		},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.168.1.1/24"}},
		}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
		Interfaces: []string{member},
	}}
	return cfg
}

// #10173: stanza spelling x member spelling x unit. Every row must scope the
// DECLARED unit key to the owning instance in the route-table maps, the
// instance map, the snapshot row, and the connected prefix's owning table —
// while the sibling unit and the control port stay out (over-reach guards).
//
// The kernel-device assertion is the in-run divergence proof: it is GREEN on
// base (#10151 fixed the kernel bind + shared resolver) while every FIB
// scoping assertion below it is RED on the cross-spelled rows.
func TestFIBBindsCrossSpelledUnitMember10173(t *testing.T) {
	units := []struct {
		num    int
		vlan   int
		prefix string
	}{
		{0, 10, "192.168.10.0/24"},
		{1, 50, "192.168.50.0/24"},
	}
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
			for _, u := range units {
				member := fmt.Sprintf("%s.%d", memberBase, u.num)
				rowKey := fmt.Sprintf("%s.%d", stanza, u.num)
				sibKey := fmt.Sprintf("%s.%d", stanza, 1-u.num)
				wantDev := fmt.Sprintf("ge-0-0-0.%d", u.vlan)
				t.Run(stanza+"/"+member, func(t *testing.T) {
					cfg := spellingCfg10173(stanza, member)
					if got := cfg.ResolveKernelIfName(member); got != wantDev {
						t.Fatalf("#10173: stanza %q member %q kernel device = %q, want %q "+
							"(the kernel side must already bind right — else this is not the FIB divergence)",
							stanza, member, got, wantDev)
					}
					if got := buildInterfaceRoutingInstances(cfg)[rowKey]; got != "blue" {
						t.Errorf("#10173: stanza %q member %q: instance map[%q] = %q, want %q",
							stanza, member, rowKey, got, "blue")
					}
					v4, v6 := buildInterfaceRouteTables(cfg)
					if got := v4[rowKey]; got != "blue.inet.0" {
						t.Errorf("#10173: stanza %q member %q: v4 table[%q] = %q, want %q",
							stanza, member, rowKey, got, "blue.inet.0")
					}
					if got := v6[rowKey]; got != "blue.inet6.0" {
						t.Errorf("#10173: stanza %q member %q: v6 table[%q] = %q, want %q",
							stanza, member, rowKey, got, "blue.inet6.0")
					}
					snap := snapshotByName9132(t, buildInterfaceSnapshots(cfg), rowKey)
					if snap.RoutingInstance != "blue" {
						t.Errorf("#10173: stanza %q member %q: snapshot %q RoutingInstance = %q, want %q",
							stanza, member, rowKey, snap.RoutingInstance, "blue")
					}
					if want := uint32(config.StableRoutingInstanceTableID("blue")); snap.RoutingDomain != want {
						t.Errorf("#10173: stanza %q member %q: snapshot %q RoutingDomain = %d, want %d (default 0 = the divergence)",
							stanza, member, rowKey, snap.RoutingDomain, want)
					}
					if got := routeTableOf9132(t, cfg, u.prefix); got != "blue.inet.0" {
						t.Errorf("#10173: stanza %q member %q: connected %s installed into %q, want %q",
							stanza, member, u.prefix, got, "blue.inet.0")
					}
					if got := buildInterfaceRoutingInstances(cfg)[sibKey]; got == "blue" {
						t.Errorf("#10173: stanza %q member %q: sibling %q dragged into blue (unit refs must not over-reach)",
							stanza, member, sibKey)
					}
					if got := routeTableOf9132(t, cfg, "192.168.1.0/24"); got != "inet.0" {
						t.Errorf("#10173: stanza %q member %q: control prefix installed into %q, want inet.0",
							stanza, member, got)
					}
				})
			}
		}
	}
}

// #10173 follow-up-request-5 parity: per-unit and interface-level tunnel rows
// in both spelling directions. The FIB keys are logical (tunnel-agnostic),
// but the kernel matrices assert both tunnel forms, so the FIB matrix does
// too — a tunnel unit claimed cross-spelled must scope its declared row.
func TestFIBBindsCrossSpelledTunnelUnit10173(t *testing.T) {
	for _, tunnel := range []struct {
		name    string
		perUnit bool
		device  string
	}{
		{"per-unit", true, "ri-unit-tun"},
		{"interface-level", false, "ge-0-0-0"},
	} {
		for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
			for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
				member := memberBase + ".1"
				rowKey := stanza + ".1"
				t.Run("tunnel/"+tunnel.name+"/"+stanza+"/"+member, func(t *testing.T) {
					cfg := spellingCfg10173(stanza, member)
					ifc := cfg.Interfaces.Interfaces[stanza]
					if tunnel.perUnit {
						ifc.Units[1].Tunnel = &config.TunnelConfig{Name: tunnel.device}
					} else {
						ifc.Tunnel = &config.TunnelConfig{
							Name:        tunnel.device,
							Source:      "10.0.0.1",
							Destination: "10.0.0.2",
						}
					}
					if got := cfg.ResolveKernelIfName(member); got != tunnel.device {
						t.Fatalf("#10173: %s tunnel stanza %q member %q kernel device = %q, want %q",
							tunnel.name, stanza, member, got, tunnel.device)
					}
					if got := buildInterfaceRoutingInstances(cfg)[rowKey]; got != "blue" {
						t.Errorf("#10173: %s tunnel stanza %q member %q: instance map[%q] = %q, want %q",
							tunnel.name, stanza, member, rowKey, got, "blue")
					}
					if got, _ := buildInterfaceRouteTables(cfg); got[rowKey] != "blue.inet.0" {
						t.Errorf("#10173: %s tunnel stanza %q member %q: v4 table[%q] = %q, want %q",
							tunnel.name, stanza, member, rowKey, got[rowKey], "blue.inet.0")
					}
					snap := snapshotByName9132(t, buildInterfaceSnapshots(cfg), rowKey)
					if snap.RoutingInstance != "blue" {
						t.Errorf("#10173: %s tunnel stanza %q member %q: snapshot RoutingInstance = %q, want %q",
							tunnel.name, stanza, member, snap.RoutingInstance, "blue")
					}
				})
			}
		}
	}
}

// #10173: a quarantined instance's cross-spelled unit member must quarantine
// the DECLARED row — else the row inherits the default session domain (the
// #9956 defect shape, in the other spelling). The survivor sub-case pins
// survivor-wins for the same collision (GREEN pre and post).
func TestFIBQuarantineCoversCrossSpelledUnitMember10173(t *testing.T) {
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
			member := memberBase + ".1"
			rowKey := stanza + ".1"
			t.Run(stanza+"/"+member, func(t *testing.T) {
				cfg := spellingCfg10173(stanza, member)
				cfg.QuarantinedRoutingInstances = cfg.RoutingInstances
				cfg.RoutingInstances = nil
				if _, ok := quarantinedInterfaceKeys(cfg)[rowKey]; !ok {
					t.Errorf("#10173: stanza %q member %q: quarantined set misses %q (have %v)",
						stanza, member, rowKey, quarantinedInterfaceKeys(cfg))
				}
				snap := snapshotByName9132(t, buildInterfaceSnapshots(cfg), rowKey)
				if snap.RoutingDomain != QuarantinedRoutingInstanceDomain {
					t.Errorf("#10173: stanza %q member %q: snapshot %q RoutingDomain = %d, want sentinel %d (0 = default-domain aliasing)",
						stanza, member, rowKey, snap.RoutingDomain, QuarantinedRoutingInstanceDomain)
				}
			})
		}
	}
	t.Run("survivor-wins", func(t *testing.T) {
		cfg := spellingCfg10173("ge-0/0/0", "ge-0/0/0.1")
		cfg.QuarantinedRoutingInstances = []*config.RoutingInstanceConfig{{
			Name: "mgmt", InstanceType: "vrf", TableID: 200,
			Interfaces: []string{"ge-0-0-0.1"},
		}}
		snap := snapshotByName9132(t, buildInterfaceSnapshots(cfg), "ge-0/0/0.1")
		if want := uint32(config.StableRoutingInstanceTableID("blue")); snap.RoutingDomain != want {
			t.Errorf("#10173 survivor-wins: snapshot RoutingDomain = %d, want survivor %d",
				snap.RoutingDomain, want)
		}
	})
}

// #10173: explicit-beats-fanout across the spelling split. tenant-a names the
// port BARE (declared spelling, fans down onto .1); tenant-b names unit 1
// EXPLICITLY (cross-spelled). The explicit unit must win in BOTH instance
// orders — the alias is an explicit binding, so it takes pass 0 like the
// as-written key. Slice order is asserted (the #9132 fixture note: position
// is decided by the slice itself here, so varying the lines varies nothing
// unless the slice is whats being varied).
func TestFIBExplicitCrossSpelledUnitBeatsFannedBare10173(t *testing.T) {
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		memberBase := "ge-0-0-0"
		if stanza == "ge-0-0-0" {
			memberBase = "ge-0/0/0"
		}
		bare := stanza
		unit := memberBase + ".1"
		unitKey := stanza + ".1"
		baseKey := stanza
		unit0Key := stanza + ".0"
		mkRI := func(name string, ifs ...string) *config.RoutingInstanceConfig {
			return &config.RoutingInstanceConfig{Name: name, InstanceType: "vrf", Interfaces: ifs}
		}
		mkCfg := func(first, second *config.RoutingInstanceConfig) *config.Config {
			cfg := spellingCfg10173(stanza, unit)
			cfg.RoutingInstances = []*config.RoutingInstanceConfig{first, second}
			return cfg
		}
		for _, order := range []struct {
			name   string
			first  string
			second string
		}{
			{"explicit-first", "tenant-b", "tenant-a"},
			{"bare-first", "tenant-a", "tenant-b"},
		} {
			t.Run(stanza+"/"+order.name, func(t *testing.T) {
				ris := map[string]*config.RoutingInstanceConfig{
					"tenant-a": mkRI("tenant-a", bare),
					"tenant-b": mkRI("tenant-b", unit),
				}
				cfg := mkCfg(ris[order.first], ris[order.second])
				if cfg.RoutingInstances[0].Name != order.first || cfg.RoutingInstances[1].Name != order.second {
					t.Fatalf("fixture: slice order not varied (got %q, %q)",
						cfg.RoutingInstances[0].Name, cfg.RoutingInstances[1].Name)
				}
				ri := buildInterfaceRoutingInstances(cfg)
				if got := ri[unitKey]; got != "tenant-b" {
					t.Errorf("#10173: stanza %q: instance map[%q] = %q, want explicit tenant-b (order %s)",
						stanza, unitKey, got, order.name)
				}
				if got, _ := buildInterfaceRouteTables(cfg); got[unitKey] != "tenant-b.inet.0" {
					t.Errorf("#10173: stanza %q: v4 table[%q] = %q, want tenant-b.inet.0 (order %s)",
						stanza, unitKey, got[unitKey], order.name)
				}
				if got := ri[unit0Key]; got != "tenant-a" {
					t.Errorf("#10173: stanza %q: instance map[%q] = %q, want fanned tenant-a (order %s)",
						stanza, unit0Key, got, order.name)
				}
				if got := ri[baseKey]; got != "tenant-a" {
					t.Errorf("#10173: stanza %q: instance map[%q] = %q, want bare tenant-a (order %s)",
						stanza, baseKey, got, order.name)
				}
			})
		}
	}
}
