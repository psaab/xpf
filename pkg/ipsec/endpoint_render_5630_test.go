package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderValidEndpoints_5630 is the render-side companion to the #5630
// commit-time endpoint gate: it pins that a VALID IPv4 / IPv6 / FQDN remote
// gateway address, and a valid local-address, still render into the swanctl
// `remote_addrs` / `local_addrs` settings unchanged. The commit-time gate
// (validateIPsecEndpointsStrict, pkg/config) rejects only endpoints strongSwan
// would refuse; this test guards that the fix does not disturb the render of
// endpoints it accepts.
func TestRenderValidEndpoints_5630(t *testing.T) {
	cases := []struct {
		name       string
		gwAddr     string
		gwLocal    string
		wantRemote string
		wantLocal  string
	}{
		{
			name:       "IPv4 remote + IPv4 local",
			gwAddr:     "203.0.113.1",
			gwLocal:    "198.51.100.7",
			wantRemote: "203.0.113.1",
			wantLocal:  "198.51.100.7",
		},
		{
			name:       "IPv6 remote + IPv6 local",
			gwAddr:     "2001:db8::1",
			gwLocal:    "2001:db8::2",
			wantRemote: "2001:db8::1",
			wantLocal:  "2001:db8::2",
		},
		{
			name:       "FQDN remote",
			gwAddr:     "peer.example.com",
			gwLocal:    "",
			wantRemote: "peer.example.com",
			wantLocal:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			cfg := &config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {Name: "gw", Address: c.gwAddr, LocalAddress: c.gwLocal},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {PSK: "fixture-secret", Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
				},
				Policies: map[string]*config.IPsecPolicyDef{
					"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
				},
				Proposals: map[string]*config.IPsecProposal{
					"prop1": {Name: "prop1", EncryptionAlg: "aes256", AuthAlg: "sha256"},
				},
			}
			// #6824: structural, not containment. The old assertions asked
			// only whether the byte sequence "remote_addrs = <addr>" appeared
			// SOMEWHERE in the document -- which a render that nested the
			// setting under the wrong connection, under children{}, or after an
			// unbalanced brace would satisfy just as well.
			conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")

			if got := conn.setting(t, "remote_addrs"); got != c.wantRemote {
				t.Errorf("connections.tun.remote_addrs = %q, want %q", got, c.wantRemote)
			}
			if c.wantLocal == "" {
				// No local-address configured: the setting must be ABSENT, not
				// merely un-searched-for. Containment could not express this.
				conn.hasNoSetting(t, "local_addrs")
			} else if got := conn.setting(t, "local_addrs"); got != c.wantLocal {
				t.Errorf("connections.tun.local_addrs = %q, want %q", got, c.wantLocal)
			}

			// The addresses belong to the CONNECTION, not to its auth rounds or
			// its child SA -- the misnesting class this issue was filed over.
			conn.at(t, "local").hasNoSetting(t, "remote_addrs")
			conn.at(t, "remote").hasNoSetting(t, "remote_addrs")
			conn.at(t, "children", "tun").hasNoSetting(t, "remote_addrs")
		})
	}
}
