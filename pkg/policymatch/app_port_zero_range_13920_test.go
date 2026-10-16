package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13920 H02-01: a deny over an application port range beginning at zero must
// match a real TCP/UDP port-zero tuple; replacing the range with 1-N let it
// fall through to the default permit. Both source and destination dimensions
// are covered for v4/v6 tuples.
func TestApplicationPortZeroRangeDenyMatchesZero_13920(t *testing.T) {
	for _, tc := range []struct {
		name             string
		proto            string
		srcPort, dstPort string
		src, dst         string
		queryProto       string
	}{
		{"tcp-source-v4", "tcp", "0-1024", "", "192.0.2.1", "198.51.100.1", "tcp"},
		{"tcp-destination-v6", "tcp", "", "0-1024", "2001:db8::1", "2001:db8::2", "tcp"},
		{"udp-source-v6", "udp", "0-1024", "", "2001:db8::1", "2001:db8::2", "udp"},
		{"udp-destination-v4", "udp", "", "0-1024", "192.0.2.1", "198.51.100.1", "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &config.Application{Name: "zero-range", Protocol: tc.proto, SourcePort: tc.srcPort, DestinationPort: tc.dstPort}
			cfg := cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{{
					Name: "deny-port-zero", Action: config.PolicyDeny,
					Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"zero-range"}},
				}}}},
			}, config.ApplicationsConfig{Applications: map[string]*config.Application{"zero-range": app}})
			q := Query{
				FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst),
				Protocol: tc.queryProto, SrcPort: 0, DstPort: 0,
			}
			res := Match(cfg, q)
			if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "deny-port-zero" {
				t.Fatalf("port-zero tuple should match deny range: got %+v", res)
			}
			q.SrcPort, q.DstPort = 1025, 1025
			res = Match(cfg, q)
			if res.Matched && res.Action == config.PolicyDeny {
				t.Fatalf("port above configured range matched deny: %+v", res)
			}
		})
	}
}
