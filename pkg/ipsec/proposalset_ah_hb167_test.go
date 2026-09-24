package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// fable-review-167 render-side coverage:
//
//	V-1 (#4297): a predefined proposal-set renders the Junos-documented
//	             swanctl proposal tokens (end-to-end: compile -> render).
//	V-2 (#4298): a `protocol ah` proposal makes renderConfig SKIP the VPN
//	             rather than emit ESP with a fabricated cipher.

func compileToIPsec(t *testing.T, lines []string) *config.IPsecConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return PrepareConfig(cfg)
}

// V-1: proposal-set standard renders the concrete swanctl proposals on both
// the Phase-1 (proposals =) and Phase-2 (esp_proposals =) lines.
//
// FAIL-ON-REVERT: without the compiler expansion the policies carry no
// resolvable proposal, so CompileConfig errors (compileToIPsec t.Fatalf) —
// the shorthand cannot commit a working tunnel.
func TestProposalSetStandardRenders_4297(t *testing.T) {
	prepared := compileToIPsec(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
	})
	conn := parseSwanctlDoc(t, New().generateConfig(prepared)).at(t, "connections", "tun1")

	// Phase-1: 3des-sha1-modp1024 (group2) and aes128-sha1-modp1024, comma-joined.
	conn.requireMembers(t, "proposals", "3des-sha1-modp1024", "aes128-sha1-modp1024")

	// Phase-2: 3des-sha1 and aes128-sha1, on the CHILD section.
	//
	// #6824: the old spelling asked whether "3des-sha1" appeared anywhere in
	// the document -- which the Phase-1 member `3des-sha1-modp1024` satisfies
	// on its own. That assertion passed whether or not esp_proposals carried
	// the ESP set, or existed at all. Membership in the split value of
	// esp_proposals at a known path cannot be satisfied by the Phase-1 line
	// nor by a longer token that merely starts the same way.
	kids := conn.at(t, "children")
	if len(kids.order) != 1 {
		t.Fatalf("expected exactly one child SA section, got %v\n%s", kids.childNames(), kids)
	}
	kids.at(t, kids.order[0]).requireMembers(t, "esp_proposals", "3des-sha1", "aes128-sha1")
}

// V-1: suiteb-gcm-128 renders the RFC 6379 AEAD tokens (aes128gcm16 + ecp256).
func TestProposalSetSuiteB128Renders_4297(t *testing.T) {
	prepared := compileToIPsec(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-sb proposal-set suiteb-gcm-128",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-sb",
		"set security ike gateway gw1 local-certificate my-cert",
		"set security ipsec policy esp-sb proposal-set suiteb-gcm-128",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-sb",
	})
	conn := parseSwanctlDoc(t, New().generateConfig(prepared)).at(t, "connections", "tun1")
	// #6824: `aes128gcm16-ecp256` is not a substring of
	// `aes128gcm16-prfsha256-ecp256`, so the two old needles did not collide --
	// but neither said WHICH line carried its token. Pin the phase.
	conn.requireMembers(t, "proposals", "aes128gcm16-prfsha256-ecp256")
	kids := conn.at(t, "children")
	if len(kids.order) != 1 {
		t.Fatalf("expected exactly one child SA section, got %v\n%s", kids.childNames(), kids)
	}
	kids.at(t, kids.order[0]).requireMembers(t, "esp_proposals", "aes128gcm16-ecp256")
}

// V-2: a VPN whose ipsec-policy resolves to a `protocol ah` proposal is
// SKIPPED at render — never emitted as ESP with a fabricated cipher — while a
// healthy ESP VPN in the same config survives.
//
// FAIL-ON-REVERT: without the vpnUsesAHProposal belt, tun-ah renders an
// esp_proposals line (aes256 default) and "tun-ah {" appears — RED.
func TestRenderConfig_AHProposalSkipsVPN_4298(t *testing.T) {
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"ah-prop":  {Name: "ah-prop", Protocol: "ah", AuthAlg: "hmac-sha-256-128"},
			"esp-prop": {Name: "esp-prop", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ah-pol":  {Name: "ah-pol", Proposals: []string{"ah-prop"}},
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-prop"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-ah":  {Name: "gw-ah", Address: "192.0.2.1"},
			"gw-esp": {Name: "gw-esp", Address: "192.0.2.2"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun-ah":  {Name: "tun-ah", Gateway: "gw-ah", IPsecPolicy: "ah-pol"},
			"tun-esp": {Name: "tun-esp", Gateway: "gw-esp", IPsecPolicy: "esp-pol"},
		},
	}
	conns := parseSwanctlDoc(t, New().generateConfig(cfg)).at(t, "connections")
	conns.hasNoChild(t, "tun-ah")
	conns.at(t, "tun-esp")
}
