package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBindlessFenceSkipsUnrenderedVPN11083 pins #11083: a bindless VPN the
// swanctl render skips (here: dangling gateway reference) gets NO fence
// rows — fencing it would drop its selectors' cleartext for SAs that will
// never establish. A renderable VPN keeps its rows.
func TestBindlessFenceSkipsUnrenderedVPN11083(t *testing.T) {
	cfg := overlayTestConfig()
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"live-vpn": {
			Name:    "live-vpn",
			Gateway: "gw1",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"corp": {LocalIP: "10.20.0.0/16", RemoteIP: "198.51.100.0/24"},
			},
		},
		"dead-vpn": {
			Name:    "dead-vpn",
			Gateway: "no-such-gateway",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"corp": {LocalIP: "10.30.0.0/16", RemoteIP: "203.0.113.0/24"},
			},
		},
	}
	cfg.Security.IPsec.Gateways = map[string]*config.IPsecGateway{
		"gw1": {Name: "gw1", Address: "192.0.2.1"},
	}
	rows := buildBindlessSelectorRows(cfg)
	for _, r := range rows {
		if r.LocalTS == "10.30.0.0/16" {
			t.Fatalf("skipped VPN got fence rows (over-drop): %+v", rows)
		}
	}
	found := false
	for _, r := range rows {
		if r.LocalTS == "10.20.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatalf("live VPN lost its fence rows: %+v", rows)
	}
}
