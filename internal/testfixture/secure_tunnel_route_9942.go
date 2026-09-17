// Package testfixture contains shared inputs for cross-package regression tests.
package testfixture

import "github.com/psaab/xpf/pkg/config"

// SecureTunnelRouteConfig9942 builds the common explicit/bare secure-tunnel and
// ordinary unit-zero route fixture used by daemon and CLI FRR tests.
func SecureTunnelRouteConfig9942(bindIface string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wan0": {Name: "wan0"},
	}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"explicit": {Name: "explicit", BindInterface: bindIface},
		"bare":     {Name: "bare", BindInterface: "st1"},
	}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{
			Destination: "10.99.0.0/16",
			NextHops:    []config.NextHopEntry{{Interface: "st0.0"}},
		},
		{
			Destination: "10.100.0.0/16",
			NextHops:    []config.NextHopEntry{{Interface: "st1.0"}},
		},
		{
			Destination: "10.101.0.0/16",
			NextHops:    []config.NextHopEntry{{Interface: "wan0.0"}},
		},
	}
	return cfg
}
