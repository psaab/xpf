package config

import (
	"strings"
	"testing"
)

// TestStaticDiscardAnchorWarnings19083 pins validateStaticDiscardAnchorWarnings19083:
// in a chassis cluster, a static whose next hop is on no configured connected
// subnet and whose longest configured covering route is a blackhole is named,
// with the discard-route migration; every control stays silent.
func TestStaticDiscardAnchorWarnings19083(t *testing.T) {
	base := func() *Config {
		c := &Config{}
		c.Chassis.Cluster = &ClusterConfig{}
		c.Interfaces.Interfaces = map[string]*InterfaceConfig{
			"reth0": {Name: "reth0", Units: map[int]*InterfaceUnit{0: {Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}}}},
		}
		return c
	}
	nh := func(a string) []NextHopEntry { return []NextHopEntry{{Address: a}} }
	cases := []struct {
		name string
		cfg  func() *Config
		want bool
	}{
		{"discard-anchor", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "198.18.0.0/16", Discard: true},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, true},
		{"reject-anchor", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "198.18.0.0/16", Reject: true},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, true},
		{"generate-anchor", func() *Config {
			c := base()
			c.RoutingOptions.GenerateRoutes = []*GenerateRoute{{Prefix: "198.18.0.0/16"}}
			c.RoutingOptions.StaticRoutes = []*StaticRoute{{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")}}
			return c
		}, true},
		{"v6-discard-anchor", func() *Config {
			c := base()
			c.RoutingOptions.Inet6StaticRoutes = []*StaticRoute{
				{Destination: "2001:db8:ff::/48", Discard: true},
				{Destination: "2001:db8:1::/64", NextHops: nh("2001:db8:ff::1")},
			}
			return c
		}, true},
		{"policy-generate-renders-nothing", func() *Config {
			c := base()
			c.RoutingOptions.GenerateRoutes = []*GenerateRoute{{Prefix: "198.18.0.0/16", Policy: "contrib"}}
			c.RoutingOptions.StaticRoutes = []*StaticRoute{{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")}}
			return c
		}, false},
		{"gateway-on-connected-subnet", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "172.16.0.0/12", Discard: true},
				{Destination: "203.0.113.0/24", NextHops: nh("172.16.50.1")},
			}
			return c
		}, false},
		{"more-specific-real-route", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "198.18.0.0/16", Discard: true},
				{Destination: "198.18.0.0/24", NextHops: nh("172.16.50.1")},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, false},
		{"recursion-via-real-default", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: nh("172.16.50.1")},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, false},
		// Codex P2 on 959251c9ee: a `no-install` discard renders nothing in
		// FRR (pkg/frr config_render.go), so with a working real default the
		// next hop resolves through the default and nothing is withdrawn.
		{"no-install-anchor-with-real-default", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: nh("172.16.50.1")},
				{Destination: "198.18.0.0/16", Discard: true, NoInstall: true},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, false},
		// The same predicate on the other side: a more-specific REAL route that
		// is not installed does not cover the next hop, so the installed
		// discard anchor still decides.
		{"no-install-real-route-does-not-cover", func() *Config {
			c := base()
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "198.18.0.0/16", Discard: true},
				{Destination: "198.18.0.0/24", NextHops: nh("172.16.50.1"), NoInstall: true},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, true},
		{"standalone", func() *Config {
			c := base()
			c.Chassis.Cluster = nil
			c.RoutingOptions.StaticRoutes = []*StaticRoute{
				{Destination: "198.18.0.0/16", Discard: true},
				{Destination: "203.0.113.0/24", NextHops: nh("198.18.0.1")},
			}
			return c
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateStaticDiscardAnchorWarnings19083(c.cfg())
			if c.want && (len(got) != 1 || !strings.Contains(got[0], "#19083") || !strings.Contains(got[0], "discard route")) {
				t.Fatalf("want one #19083 warning with the discard-route migration, got %q", got)
			}
			if !c.want && len(got) != 0 {
				t.Fatalf("want no warning, got %q", got)
			}
		})
	}
}

// TestStrictCommitRefusesStaticNHTMapNames19083 pins the existing reserved
// suffix rule (#12065) for the two generated #19083 map names: a strict commit
// refuses an operator policy-statement with either name.
func TestStrictCommitRefusesStaticNHTMapNames19083(t *testing.T) {
	for _, name := range []string{"xpf-static-nht-xpf-redist", "xpf-static-nht-b-xpf-redist"} {
		c := &Config{}
		c.PolicyOptions.PolicyStatements = map[string]*PolicyStatement{name: {Name: name}}
		if err := validatePolicyReservedRedistNameStrict(c); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("strict validation accepted an operator policy named %q: %v", name, err)
		}
	}
}
