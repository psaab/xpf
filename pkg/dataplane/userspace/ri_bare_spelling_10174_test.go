package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #10174: a BARE cross-spelled member (base == member) must fan down through
// the declared stanza in the userspace FIB. The alias is deliberately not
// centralized in Config.SplitInterfaceUnitRef (#8829/#9821): the daemon and
// userspace consumers own their Linux-name matching. A bare dash member
// against a slash stanza currently reaches only its as-written key, which no
// snapshot row has, so addressed rows stay in the default table.
func spellingCfg10174(stanza, member string) *config.Config {
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

// #10174: both Linux spelling directions must scope the base and every
// addressed unit row to the same routing instance. The control port proves the
// default table remains populated, and the exact unit-row assertions prove
// this is fan-down rather than a coincidental base claim.
func TestFIBBareCrossSpelledMemberFansDown10174(t *testing.T) {
	for _, tc := range []struct {
		stanza string
		member string
	}{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0/0/0"},
	} {
		t.Run(tc.stanza+"/"+tc.member, func(t *testing.T) {
			cfg := spellingCfg10174(tc.stanza, tc.member)
			base := tc.stanza
			unit0 := tc.stanza + ".0"
			unit1 := tc.stanza + ".1"
			for _, key := range []string{base, unit0, unit1} {
				if got := buildInterfaceRoutingInstances(cfg)[key]; got != "blue" {
					t.Errorf("#10174: bare member %q stanza %q: instance map[%q] = %q, want blue",
						tc.member, tc.stanza, key, got)
				}
				v4, v6 := buildInterfaceRouteTables(cfg)
				if got := v4[key]; got != "blue.inet.0" {
					t.Errorf("#10174: bare member %q stanza %q: v4 table[%q] = %q, want blue.inet.0",
						tc.member, tc.stanza, key, got)
				}
				if got := v6[key]; got != "blue.inet6.0" {
					t.Errorf("#10174: bare member %q stanza %q: v6 table[%q] = %q, want blue.inet6.0",
						tc.member, tc.stanza, key, got)
				}
			}
			for _, row := range []struct {
				name   string
				prefix string
			}{
				{unit0, "192.168.10.0/24"},
				{unit1, "192.168.50.0/24"},
			} {
				snap := snapshotByName9132(t, buildInterfaceSnapshots(cfg), row.name)
				if snap.RoutingInstance != "blue" {
					t.Errorf("#10174: bare member %q stanza %q: snapshot %q RoutingInstance = %q, want blue",
						tc.member, tc.stanza, row.name, snap.RoutingInstance)
				}
				if want := uint32(config.StableRoutingInstanceTableID("blue")); snap.RoutingDomain != want {
					t.Errorf("#10174: bare member %q stanza %q: snapshot %q RoutingDomain = %d, want %d",
						tc.member, tc.stanza, row.name, snap.RoutingDomain, want)
				}
				if got := routeTableOf9132(t, cfg, row.prefix); got != "blue.inet.0" {
					t.Errorf("#10174: bare member %q stanza %q: connected %s installed into %q, want blue.inet.0",
						tc.member, tc.stanza, row.prefix, got)
				}
			}
			if got := routeTableOf9132(t, cfg, "192.168.1.0/24"); got != "inet.0" {
				t.Errorf("#10174: control prefix installed into %q, want inet.0", got)
			}

			// The #9815 claimedBare partition already carries the raw Linux
			// alias, so a bare cross-spelled claim must exclude the whole
			// declared port from default-instance next-table ingress as well.
			gotIngress := routing.DefaultInstanceIngressIfaces(cfg)
			if strings.Join(gotIngress, ",") != "ge-0-0-1" {
				t.Errorf("#10174: bare member %q stanza %q: default ingress = %v, want [ge-0-0-1]",
					tc.member, tc.stanza, gotIngress)
			}
		})
	}
}
