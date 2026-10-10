package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func buildRAWithPD10856(t *testing.T, cfg *config.Config, prefix string) []*config.RAInterfaceConfig {
	t.Helper()
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("wan0", "lan0", []dhcp.DelegatedPrefix{{
		Interface: "wan0", Prefix: netip.MustParsePrefix(prefix),
	}})
	return (&Daemon{dhcp: mgr}).buildRAConfigs(cfg)
}

func TestBuildRAConfigsRejectsConfiguredIPv6Overlap10856(t *testing.T) {
	const pd = "2606:4700:4700:1000::/64"
	for _, tc := range []struct {
		name string
		cfg  func() *config.Config
	}{
		{
			name: "interface address",
			cfg: func() *config.Config {
				return &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
					"lan0": {Units: map[int]*config.InterfaceUnit{0: {Addresses: []string{"2606:4700:4700:1000::1/64"}}}},
				}}}
			},
		},
		{
			name: "static RA prefix",
			cfg: func() *config.Config {
				return &config.Config{Protocols: config.ProtocolsConfig{RouterAdvertisement: []*config.RAInterfaceConfig{{
					Interface: "lan0", Prefixes: []*config.RAPrefix{{Prefix: pd}},
				}}}}
			},
		},
		{
			name: "RA NAT64 prefix",
			cfg: func() *config.Config {
				return &config.Config{Protocols: config.ProtocolsConfig{RouterAdvertisement: []*config.RAInterfaceConfig{{
					Interface: "lan0", NAT64Prefix: "2606:4700:4700:1000::/96",
				}}}}
			},
		},
		{
			name: "configured NAT64 prefix",
			cfg: func() *config.Config {
				return &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{
					NAT64: []*config.NAT64RuleSet{{Prefix: "2606:4700:4700:1000::/96"}},
				}}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, ra := range buildRAWithPD10856(t, tc.cfg(), pd) {
				for _, pfx := range ra.Prefixes {
					if pfx.Delegated {
						t.Fatalf("overlapping delegated prefix %s was included in RA config", pfx.Prefix)
					}
				}
			}
		})
	}
}

func TestBuildRAConfigsKeepsNonOverlappingGUADelegation10856(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"lan0": {Units: map[int]*config.InterfaceUnit{0: {Addresses: []string{"2606:4700:4701::1/64"}}}},
	}}}
	const pd = "2606:4700:4700:1000::/64"
	found := false
	for _, ra := range buildRAWithPD10856(t, cfg, pd) {
		for _, pfx := range ra.Prefixes {
			found = found || (pfx.Delegated && pfx.Prefix == pd)
		}
	}
	if !found {
		t.Fatalf("non-overlapping GUA delegation %s was not built into an RA config", pd)
	}
}
