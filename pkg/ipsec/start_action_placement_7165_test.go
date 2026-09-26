package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7165 item 2: `start_action` is a CHILD setting in swanctl.conf, never a
// connection setting.
//
// The renderer emitted it in BOTH places, and strongSwan 6.0.5 rejects the
// connection outright rather than ignoring the stray key:
//
//	loading connection 'vpn-a' failed: unknown option: start_action, config discarded
//	loaded 0 of 1 connections, 1 failed to load, 0 unloaded
//
// "config discarded" is the WHOLE connection. So every VPN configured with
// `establish-tunnels immediately` generated a config strongSwan refused
// entirely, and IPsec did not come up. Removing the connection-level line and
// changing nothing else makes the same config load: `loaded connection 'vpn-a',
// successfully loaded 1 connections`, verified against a live charon.
//
// WHY NO TEST CAUGHT IT, which is the part worth keeping. Every renderer test
// asserts on the emitted TEXT, and a text assertion cannot know which keys
// strongSwan accepts — it will happily confirm that a line strongSwan rejects
// was emitted correctly. That is the exact gap #7165 item 2 was filed about
// ("no proof that generated config actually LOADS"), and the first thing the
// proof did was find this.
//
// This test cannot close that gap either — only loading against a real charon
// can, and that needs a lab node (procedure in docs/ipsec-swanctl-load-proof.md).
// What it CAN do is pin the structural rule the load proved, so the specific
// defect cannot come back silently.

func renderImmediateVPN(t *testing.T) string {
	t.Helper()
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {
				Name: "ike-prop", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256",
				DHGroup: 14, LifetimeSeconds: 3600,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Mode: "main", Proposals: []string{"ike-prop"}, PSK: config.Secret("secret123")},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-a": {
				Name: "gw-a", Address: "203.0.113.1", LocalAddress: "198.51.100.7",
				IKEPolicy: "ike-pol", ExternalIface: "ge-0-0-2",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-prop": {
				Name: "esp-prop", Protocol: "esp",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256",
				DHGroup: 14, LifetimeSeconds: 3600,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-prop"}, PFSGroup: 14},
		},
		VPNs: map[string]*config.IPsecVPN{
			// `immediately` requests start_action = start.
			"vpn-a": {
				Name: "vpn-a", Gateway: "gw-a", IPsecPolicy: "ipsec-pol",
				BindInterface: "st0.0", EstablishTunnels: "immediately",
			},
		},
	}
	rendered, _, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	// Parsed, not string-matched. TestNoSwanctlSyntaxInContainmentNeedles_6824
	// forbids a Contains needle spelling swanctl syntax, and it is right for
	// exactly the reason this issue exists: a byte check cannot say which
	// SECTION a setting landed in, which is the entire defect here.
	doc := parseSwanctlDoc(t, rendered)
	if _, ok := doc.at(t, "connections").children["vpn-a"]; !ok {
		t.Fatalf("fixture rendered no connection at all, so nothing below is being "+
			"asserted — a skipped VPN passes every check in this file. Got:\n%s", rendered)
	}
	return rendered
}

func TestStartActionIsChildOnly7165(t *testing.T) {
	doc := parseSwanctlDoc(t, renderImmediateVPN(t))

	// The connection section must NOT carry it. This is the defect: strongSwan
	// answers "unknown option: start_action, config discarded" and drops the
	// ENTIRE connection, so IPsec does not come up for a VPN with
	// establish-tunnels immediately (#7165).
	doc.at(t, "connections", "vpn-a").hasNoSetting(t, "start_action")

	// And the child section MUST. Not decoration: a fix that deleted both
	// emits would satisfy the assertion above while silently dropping the
	// behaviour the operator asked for, leaving a connection that loads and
	// never initiates.
	doc.at(t, "connections", "vpn-a", "children", "vpn-a").
		requireSetting(t, "start_action", "start")
}

// Control: when establish-tunnels is unset, start_action must not appear.
// This distinguishes the default responder behavior from the explicit
// on-demand `trap` mode.
func TestStartActionAbsentWhenEstablishTunnelsUnset7165(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {Name: "ike-prop", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Mode: "main", Proposals: []string{"ike-prop"}, PSK: config.Secret("s")},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-prop": {Name: "esp-prop", Protocol: "esp", EncryptionAlg: "aes-256-cbc",
				AuthAlg: "hmac-sha-256", DHGroup: 14, LifetimeSeconds: 3600},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-prop"}, PFSGroup: 14},
		},
		VPNs: map[string]*config.IPsecVPN{
			"vpn-a": {Name: "vpn-a", Gateway: "gw-a", IPsecPolicy: "ipsec-pol", BindInterface: "st0.0"},
		},
	}
	rendered, _, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	doc := parseSwanctlDoc(t, rendered)
	conn := doc.at(t, "connections", "vpn-a")
	conn.hasNoSetting(t, "start_action")
	conn.at(t, "children", "vpn-a").hasNoSetting(t, "start_action")
}
