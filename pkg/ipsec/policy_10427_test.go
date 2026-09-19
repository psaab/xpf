package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEffectiveTrafficSelectorsOneSidedWildcard10427 covers the half-empty gap
// left by #8003 at the rendered swanctl layer: in route-based mode (if_id > 0)
// EACH empty side defaults to routeBasedDefaultTS independently. An operator
// who sets local-identity to a selector-shaped CIDR while omitting
// remote-identity must get a wildcard remote_ts — not an omitted key that
// strongSwan resolves to the peer's /32 endpoint address (measured on
// strongSwan 6.0.5), silently blackholing routed transit traffic.
//
// Fail-on-revert: reverting the per-side default in effectiveTrafficSelectors
// makes the rendered local-only and remote-only cells lose their wildcard
// setting and go RED.
func TestEffectiveTrafficSelectorsOneSidedWildcard10427(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		bindIface                 string
		localID, remoteID         string
		wantLocalTS, wantRemoteTS string
	}{
		// The subjects: one-sided identities on a route-based VPN.
		{"route-based local-only gets remote wildcard", "st0.0", "10.10.0.0/16", "", "10.10.0.0/16", routeBasedDefaultTS},
		{"route-based remote-only gets local wildcard", "st0.0", "", "10.20.0.0/16", routeBasedDefaultTS, "10.20.0.0/16"},

		// Controls: both-empty and both-set behavior is unchanged.
		{"route-based both-empty stays dual wildcard", "st0.0", "", "", routeBasedDefaultTS, routeBasedDefaultTS},
		{"route-based both-set unchanged", "st0.0", "10.10.0.0/16", "10.20.0.0/16", "10.10.0.0/16", "10.20.0.0/16"},

		// Belt interaction: a non-selector remote is dropped by the #8003
		// belt, leaving that side empty, so the per-side default fills it.
		{"route-based local cidr remote fqdn gets remote wildcard", "st0.0", "10.10.0.0/16", "peer.example.com", "10.10.0.0/16", routeBasedDefaultTS},

		// Policy-based VPNs are untouched: the selector IS the enforcement
		// boundary there, so no default may apply on either side.
		{"policy-based local-only stays narrow", "", "10.10.0.0/16", "", "10.10.0.0/16", ""},
		{"policy-based both-empty stays dynamic", "", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.IPsecConfig{
				VPNs: map[string]*config.IPsecVPN{
					"v1": {
						Name:          "v1",
						Gateway:       "192.0.2.1",
						BindInterface: tc.bindIface,
						LocalID:       tc.localID,
						RemoteID:      tc.remoteID,
					},
				},
				Proposals: map[string]*config.IPsecProposal{},
			}
			doc := parseSwanctlDoc(t, (&Manager{}).generateConfig(cfg))
			child := doc.at(t, "connections", "v1", "children", "v1")
			if tc.wantLocalTS == "" {
				child.hasNoSetting(t, "local_ts")
			} else {
				child.requireSetting(t, "local_ts", tc.wantLocalTS)
			}
			if tc.wantRemoteTS == "" {
				child.hasNoSetting(t, "remote_ts")
			} else {
				child.requireSetting(t, "remote_ts", tc.wantRemoteTS)
			}
		})
	}
}
