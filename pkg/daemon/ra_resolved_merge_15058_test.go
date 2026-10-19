package daemon

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

// #15058 (A26-04): a static RA authored as ge-0/0/1.0 and a PD
// update-router-advertisement target authored as ge-0/0/1 resolve to the
// same kernel netdev (ge-0-0-1, unit 0 collapses). buildRAConfigs keyed its
// merge map by the raw authored string, so the PD prefix created a second
// RA config for the same netdev; the final ResolveKernelIfName pass then
// produced two configs named ge-0-0-1 and ra.Apply's last-wins desired map
// silently dropped the static config (M/O flags, RDNSS, static PIOs).

func raMergeFixture15058(t *testing.T, staticIface, pdIface string) []*config.RAInterfaceConfig {
	t.Helper()
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", pdIface, []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:aaaa::/64"),
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     7200 * time.Second,
	}})
	d := &Daemon{dhcp: mgr}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/1": {
					Name: "ge-0/0/1",
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:db8:1::1/64"}},
					},
				},
				"ge-0/0/2": {
					Name: "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"2001:db8:2::1/64"}},
					},
				},
			},
		},
		Protocols: config.ProtocolsConfig{
			RouterAdvertisement: []*config.RAInterfaceConfig{{
				Interface:     staticIface,
				ManagedConfig: true,
				OtherStateful: true,
				DNSServers:    []string{"2001:db8::53"},
				Prefixes: []*config.RAPrefix{
					{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true},
				},
			}},
		},
	}
	return d.buildRAConfigs(cfg)
}

func TestBuildRAConfigs15058StaticDotZeroMergesPD(t *testing.T) {
	for _, tc := range []struct {
		name        string
		staticIface string
		pdIface     string
	}{
		{"static unit0 PD bare", "ge-0/0/1.0", "ge-0/0/1"},
		{"static bare PD unit0", "ge-0/0/1", "ge-0/0/1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ras := raMergeFixture15058(t, tc.staticIface, tc.pdIface)
			if len(ras) != 1 {
				t.Fatalf("buildRAConfigs returned %d RA configs, want 1 merged config for ge-0-0-1: %+v", len(ras), ras)
			}
			ra := ras[0]
			if ra.Interface != "ge-0-0-1" {
				t.Fatalf("Interface = %q, want ge-0-0-1", ra.Interface)
			}
			if !ra.ManagedConfig || !ra.OtherStateful {
				t.Errorf("M/O flags = %v/%v, want true/true (static options must survive PD merge)", ra.ManagedConfig, ra.OtherStateful)
			}
			if len(ra.DNSServers) != 1 || ra.DNSServers[0] != "2001:db8::53" {
				t.Errorf("DNSServers = %v, want [2001:db8::53] (static RDNSS must survive)", ra.DNSServers)
			}
			got := map[string]bool{}
			for _, p := range ra.Prefixes {
				got[p.Prefix] = true
			}
			if !got["2001:db8:1::/64"] || !got["2001:db8:aaaa::/64"] {
				t.Errorf("prefixes = %v, want both static 2001:db8:1::/64 and delegated 2001:db8:aaaa::/64", got)
			}
		})
	}
}

// Control: PD targeting a genuinely different interface stays separate.
func TestBuildRAConfigs15058DistinctInterfacesStaySeparate(t *testing.T) {
	ras := raMergeFixture15058(t, "ge-0/0/1.0", "ge-0/0/2")
	if len(ras) != 2 {
		t.Fatalf("buildRAConfigs returned %d RA configs, want 2 distinct interfaces", len(ras))
	}
	byIface := map[string]*config.RAInterfaceConfig{}
	for _, ra := range ras {
		byIface[ra.Interface] = ra
	}
	staticRA, ok := byIface["ge-0-0-1"]
	if !ok || !staticRA.ManagedConfig || len(staticRA.Prefixes) != 1 {
		t.Errorf("static ge-0-0-1 = %+v, want managed with only its static prefix", staticRA)
	}
	pdRA, ok := byIface["ge-0-0-2"]
	if !ok || len(pdRA.Prefixes) != 1 || pdRA.Prefixes[0].Prefix != "2001:db8:aaaa::/64" {
		t.Errorf("PD ge-0-0-2 = %+v, want only the delegated prefix", pdRA)
	}
}
