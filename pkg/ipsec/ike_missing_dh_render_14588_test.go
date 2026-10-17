package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14588 (Y09-01) render cells: a lenient-loaded (or directly
// constructed) IKE proposal with NO dh-group must SKIP its VPN at
// render rather than emit `proposals = aes256-sha256` — a proposal
// with no key-exchange method that makes charon discard the whole
// file ("invalid value for: proposals, config discarded, loaded 0 of
// 1"). The healthy sibling must still render, so other VPNs load with
// swanctl rc 0. On revert (no missing-DH check in
// resolveIKESettings), the DH-less VPN renders and these cells go RED.

func missingDHConfig14588() *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"bad":  {Name: "bad", Gateway: "gw-bad", IPsecPolicy: "esp-pol", PSK: "fixture-secret"},
			"good": {Name: "good", Gateway: "gw-good", IPsecPolicy: "esp-pol", PSK: "fixture-secret"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-bad":  {Name: "gw-bad", Address: "192.0.2.1", IKEPolicy: "ike-pol-bad"},
			"gw-good": {Name: "gw-good", Address: "192.0.2.2", IKEPolicy: "ike-pol-good"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol-bad":  {Name: "ike-pol-bad", Proposals: []string{"ike-bad"}},
			"ike-pol-good": {Name: "ike-pol-good", Proposals: []string{"ike-good"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			// No DHGroup: renders `aes256-sha256` (no key exchange).
			"ike-bad":  {Name: "ike-bad", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256"},
			"ike-good": {Name: "ike-good", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-p2"}},
		},
	}
}

// TestRenderSkipsIKEProposalNoDHGroup14588 is the render-level
// acceptance cell: the DH-less VPN is absent from the rendered config
// and from the rendered set, the healthy VPN still renders with a
// loadable proposal, and no `proposals = aes256-sha256` (key-exchange
// -less) line reaches the file.
func TestRenderSkipsIKEProposalNoDHGroup14588(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}
	text, rendered, err := m.renderConfig(missingDHConfig14588())
	if err != nil {
		t.Fatalf("renderConfig must skip the DH-less VPN, not abort the whole render: %v", err)
	}
	if rendered["bad"] {
		t.Errorf("DH-less VPN rendered; charon would discard the whole file")
	}
	if !rendered["good"] {
		t.Errorf("healthy sibling VPN did not render; rendered=%v", rendered)
	}
	doc := parseSwanctlDoc(t, text)
	conns := doc.at(t, "connections")
	// The DH-less connection must not exist at all (structural, per
	// #6824 — no containment needles).
	conns.hasNoChild(t, "bad")
	// The healthy connection renders with its DH term.
	good := conns.at(t, "good")
	good.requireSetting(t, "proposals", "aes256-sha256-modp2048")
	// No orphan secret for the skipped VPN.
	secrets := doc.at(t, "secrets")
	secrets.hasNoChild(t, "ike-bad")
	secrets.at(t, "ike-good")
}

// TestResolveIKESettingsNoDHGroupSentinel14588 pins the resolver-level
// contract: a DH-less IKE proposal surfaces as errDHGroupUnresolved
// (skip-class), so renderConfig's existing skip arm handles it — the
// same sentinel the bad-DH (#9919) path uses.
func TestResolveIKESettingsNoDHGroupSentinel14588(t *testing.T) {
	cfg := missingDHConfig14588()
	_, _, _, _, err := resolveIKESettings(cfg, cfg.Gateways["gw-bad"])
	if err == nil {
		t.Fatal("resolveIKESettings accepted a DH-less IKE proposal; want errDHGroupUnresolved")
	}
	if !errors.Is(err, errDHGroupUnresolved) {
		t.Errorf("resolveIKESettings error = %v, want errDHGroupUnresolved (skip-class)", err)
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Errorf("error does not name dh-group: %v", err)
	}
}

// TestResolveIKESettingsLegacyNoDHGroup14588 pins the legacy
// direct-proposal fallback: the ike-policy value names an IPsec
// proposal; a DH-less one must skip the same way.
func TestResolveIKESettingsLegacyNoDHGroup14588(t *testing.T) {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "192.0.2.1", IKEPolicy: "esp-legacy"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-legacy": {Name: "esp-legacy", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}
	_, _, _, _, err := resolveIKESettings(cfg, cfg.Gateways["gw"])
	if err == nil {
		t.Fatal("resolveIKESettings accepted a DH-less legacy IKE proposal; want errDHGroupUnresolved")
	}
	if !errors.Is(err, errDHGroupUnresolved) {
		t.Errorf("error = %v, want errDHGroupUnresolved", err)
	}
}

// TestBuildIKEProposalNoDHRendersKeyExchangeLess14588 documents the
// mechanism the skip protects against: the builders omit the DH term
// at DHGroup 0. This is not a fix assertion — it pins WHY the resolver
// must never let such a proposal through.
func TestBuildIKEProposalNoDHRendersKeyExchangeLess14588(t *testing.T) {
	if got := buildIKEProposalFromIKE(&config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256"}); got != "aes256-sha256" {
		t.Fatalf("buildIKEProposalFromIKE(DHGroup 0) = %q, want %q (the charon-refused shape)", got, "aes256-sha256")
	}
}
