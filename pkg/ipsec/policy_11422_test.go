package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestExplicitRouteBasedSelectorsDefaultEachEmptySide11422(t *testing.T) {
	for _, tc := range []struct {
		name       string
		local      string
		remote     string
		wantLocal  string
		wantRemote string
	}{
		{
			name:       "local-only explicit selector",
			local:      "10.1.0.0/24",
			wantLocal:  "10.1.0.0/24",
			wantRemote: config.IPsecRouteBasedDefaultTrafficSelector,
		},
		{
			name:       "remote-only explicit selector",
			remote:     "10.2.0.0/24",
			wantLocal:  config.IPsecRouteBasedDefaultTrafficSelector,
			wantRemote: "10.2.0.0/24",
		},
		{
			name:       "both explicit sides preserved",
			local:      "10.1.0.0/24",
			remote:     "10.2.0.0/24",
			wantLocal:  "10.1.0.0/24",
			wantRemote: "10.2.0.0/24",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vpn := &config.IPsecVPN{
				BindInterface: "st0.0",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"to-peer": {LocalIP: tc.local, RemoteIP: tc.remote},
				},
			}
			got := effectiveTrafficSelectors("site", vpn)
			if len(got) != 1 {
				t.Fatalf("effectiveTrafficSelectors returned %d children, want 1", len(got))
			}
			if got[0].LocalTS != tc.wantLocal || got[0].RemoteTS != tc.wantRemote {
				t.Fatalf("rendered selectors = (%q, %q), want (%q, %q)",
					got[0].LocalTS, got[0].RemoteTS, tc.wantLocal, tc.wantRemote)
			}
		})
	}
}
