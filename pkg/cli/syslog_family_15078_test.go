package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15078 (A47-01) CLI mirror: the in-process commit path must resolve the
// source against the collector's family exactly as the daemon does
// (#5738/#6875 parity). FAIL-ON-REVERT: family-blind resolution binds
// the IPv4 primary (10.0.1.20) for the IPv6 collector cells.
func TestBuildSyslogClientsCollectorFamily15078(t *testing.T) {
	base := func() *config.Config {
		cfg := &config.Config{}
		cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
				100: {
					Number:           100,
					Addresses:        []string{"10.0.1.20/24", "2001:db8:1::20/64"},
					PrimaryAddress:   "10.0.1.20/24",
					PreferredAddress: "10.0.1.20/24",
				},
			}},
		}
		return cfg
	}
	for _, tc := range []struct {
		name           string
		host           string
		perStreamIface string
		globalIface    string
		want           string
	}{
		{"ipv6 collector via per-stream source-interface", "2001:db8:9::1", "reth1.100", "", "2001:db8:1::20"},
		{"ipv6 collector via global source-interface", "2001:db8:9::1", "", "reth1.100", "2001:db8:1::20"},
		{"ipv4 collector control", "192.0.2.1", "reth1.100", "", "10.0.1.20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			cfg.Security.Log.SourceInterface = tc.globalIface
			cfg.Security.Log.Streams = map[string]*config.SyslogStream{
				"audit": {
					Name:            "audit",
					Host:            tc.host,
					Port:            514,
					Transport:       config.SyslogTransport{Protocol: "tcp"},
					SourceInterface: tc.perStreamIface,
				},
			}
			clients := buildSyslogClients(cfg)
			if len(clients) != 1 {
				t.Fatalf("expected 1 syslog client, got %d", len(clients))
			}
			defer clients[0].Close()
			if got := clients[0].SourceAddr(); got != tc.want {
				t.Errorf("CLI path bound source %q, want %q (#15078)", got, tc.want)
			}
		})
	}
}
