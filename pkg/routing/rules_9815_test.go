package routing

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9815 SYN-VRF-02: DefaultInstanceIngressIfaces misreads a routing-instance
// member whose spelling differs from its stanza. The claim is recorded raw +
// resolved, but the resolver looks the stanza up by the raw base, so a dash
// claim against a slash stanza resolves verbatim (ge-0-0-0.1) while the unit
// itself resolves to its VLAN device (ge-0-0-0.50) — and the whole-port skip
// keys on the raw stanza spelling. The claimed units stay in the
// default-instance scoping set, and the #9420 applier emits default-instance
// next-table iif rules for them.
//
// spellingCfg9815 is the issue's probe: stanza ge-0/0/0 (either spelling) with
// unit 0 on vlan 10 and unit 1 on vlan 50, plus an unclaimed control port so
// the set is never vacuously empty.
func spellingCfg9815(stanza, member string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		stanza: {
			Name:        stanza,
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, VlanID: 10},
				1: {Number: 1, VlanID: 50},
			},
		},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
		Interfaces: []string{member},
	}}
	return cfg
}

// #9815 SYN-VRF-02: stanza spelling x member spelling x member shape. A claim
// in either spelling must exclude the same devices: bare excludes the whole
// port, a unit ref excludes exactly that unit's VLAN device.
func TestDefaultInstanceIngressExcludesEitherSpelling9815(t *testing.T) {
	for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
		for _, tc := range []struct {
			shape string
			want  string
		}{
			{"", "ge-0-0-1"},
			{".0", "ge-0-0-0.50,ge-0-0-1"},
			{".1", "ge-0-0-0.10,ge-0-0-1"},
		} {
			for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
				member := memberBase + tc.shape
				t.Run(stanza+"/"+member, func(t *testing.T) {
					got := DefaultInstanceIngressIfaces(spellingCfg9815(stanza, member))
					if strings.Join(got, ",") != tc.want {
						t.Fatalf("#9815: stanza %q member %q: default ingress = %v, want [%s]",
							stanza, member, got, tc.want)
					}
				})
			}
		}
	}
	// A cross-spelled claim must also exclude tunnel devices from the
	// default-instance scope: per-unit tunnels use their own device and
	// interface-level tunnels share the stanza's base. Test both directions.
	for _, tunnel := range []struct {
		name    string
		perUnit bool
		want    string
	}{
		{"per-unit", true, "ge-0-0-0.10,ge-0-0-1"},
		{"interface-level", false, "ge-0-0-1"},
	} {
		for _, stanza := range []string{"ge-0/0/0", "ge-0-0-0"} {
			for _, memberBase := range []string{"ge-0/0/0", "ge-0-0-0"} {
				member := memberBase + ".1"
				t.Run("tunnel/"+tunnel.name+"/"+stanza+"/"+member, func(t *testing.T) {
					cfg := spellingCfg9815(stanza, member)
					ifc := cfg.Interfaces.Interfaces[stanza]
					if tunnel.perUnit {
						ifc.Units[1].Tunnel = &config.TunnelConfig{Name: "ri-unit-tun"}
					} else {
						ifc.Tunnel = &config.TunnelConfig{
							Name:        "ge-0-0-0",
							Source:      "10.0.0.1",
							Destination: "10.0.0.2",
						}
					}
					got := DefaultInstanceIngressIfaces(cfg)
					if strings.Join(got, ",") != tunnel.want {
						t.Fatalf("#9815: %s tunnel stanza %q member %q: default ingress = %v, want [%s]",
							tunnel.name, stanza, member, got, tunnel.want)
					}
				})
			}
		}
	}
}
