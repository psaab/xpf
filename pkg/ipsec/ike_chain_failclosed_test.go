package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2270 render-side fail-closed coverage. resolveIKESettings must
// distinguish the intentional no-policy case (empty proposal, nil error)
// from a broken ike-policy chain (errIKEChainUnresolved), so renderConfig
// never silently emits a proposal-less connection that strongSwan would
// negotiate with its compiled-in defaults.

// resolveIKESettings returns a nil error and an empty proposal for the
// intentional no-policy case.
func TestResolveIKESettings_NoPolicyOK(t *testing.T) {
	cfg := &config.IPsecConfig{}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err != nil {
		t.Fatalf("no-policy gateway must not error: %v", err)
	}
	if prop != "" {
		t.Errorf("no-policy gateway proposal = %q, want empty (strongSwan default chosen)", prop)
	}
}

// resolveIKESettings returns errIKEChainUnresolved when the gateway names
// an undefined ike-policy.
func TestResolveIKESettings_DanglingPolicyFailsClosed(t *testing.T) {
	cfg := &config.IPsecConfig{}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "does-not-exist"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err == nil {
		t.Fatal("dangling ike-policy must fail closed, got nil error")
	}
	if !errors.Is(err, errIKEChainUnresolved) {
		t.Errorf("error = %v, want errIKEChainUnresolved", err)
	}
	if prop != "" {
		t.Errorf("broken chain proposal = %q, want empty", prop)
	}
}

// resolveIKESettings returns errIKEChainUnresolved when the ike-policy
// resolves but its `proposals` reference dangles.
func TestResolveIKESettings_DanglingProposalFailsClosed(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"no-such-proposal"}},
		},
	}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"}
	_, _, _, _, err := resolveIKESettings(cfg, gw)
	if !errors.Is(err, errIKEChainUnresolved) {
		t.Fatalf("dangling proposal must fail closed with errIKEChainUnresolved, got: %v", err)
	}
}

// A fully resolvable chain returns the built proposal with no error.
func TestResolveIKESettings_ResolvableChain(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-prop"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {
				Name:          "ike-prop",
				AuthMethod:    "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
	}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err != nil {
		t.Fatalf("resolvable chain errored: %v", err)
	}
	if prop == "" {
		t.Fatal("resolvable chain produced an empty proposal")
	}
	if !strings.Contains(prop, "aes256") {
		t.Errorf("proposal %q missing encryption token", prop)
	}
}

// renderConfig SKIPS a VPN whose ike-policy chain is broken (so its
// connection and secret are omitted) while a healthy tunnel in the same
// config renders normally with a `proposals =` line. One bad reference
// never zeroes a healthy tunnel, and a proposal-less connection is never
// written for the broken one.
func TestRenderConfig_BrokenChainSkipsVPN_HealthyTunnelSurvives(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"good-pol": {Name: "good-pol", Proposals: []string{"good-prop"}, PSK: "secret-good"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"good-prop": {
				Name:          "good-prop",
				AuthMethod:    "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-good": {Name: "gw-good", Address: "192.0.2.1", IKEPolicy: "good-pol"},
			"gw-bad":  {Name: "gw-bad", Address: "192.0.2.2", IKEPolicy: "missing-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun-good": {PSK: "fixture-secret", Name: "tun-good", Gateway: "gw-good"},
			"tun-bad":  {PSK: "fixture-secret", Name: "tun-bad", Gateway: "gw-bad"},
		},
	}

	m := New()
	out := m.generateConfig(cfg)

	doc := parseSwanctlDoc(t, out)

	// Healthy tunnel: connection section present, with a non-empty Phase-1
	// proposals line carrying the configured crypto.
	//
	// #6824: this previously had to match the four-space-indented
	// "\n    proposals = aes256" to avoid FALSE-PASSING off the child
	// "        esp_proposals = aes256..." line -- an assertion about
	// INDENTATION standing in for one about nesting. Reading the setting at
	// connections.tun-good states it directly, and the child section's
	// esp_proposals cannot satisfy it at any indentation.
	// #15024: connections are gateway-named (gw-good/gw-bad), children keep VPN names.
	good := doc.at(t, "connections", "gw-good")
	if p := good.setting(t, "proposals"); !strings.HasPrefix(p, "aes256") {
		t.Errorf("connections.gw-good.proposals = %q, want it to carry aes256", p)
	}
	good.at(t, "children", "tun-good")

	// Broken tunnel: connection section must NOT be emitted (no proposal-less
	// connection that would negotiate with strongSwan defaults).
	doc.at(t, "connections").hasNoChild(t, "gw-bad")
	doc.at(t, "connections").hasNoChild(t, "tun-bad")
	// And its secret must not be orphaned in the secrets block.
	doc.at(t, "secrets").hasNoChild(t, "ike-gw-bad")
}

// A no-policy gateway renders a normal connection WITHOUT a proposals line
// (the intentional default case) and is NOT skipped.
func TestRenderConfig_NoPolicyGatewayRendersWithoutProposalsLine(t *testing.T) {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "192.0.2.1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {PSK: "fixture-secret", Name: "tun1", Gateway: "gw1"},
		},
	}
	m := New()
	out := m.generateConfig(cfg)
	conn := parseSwanctlDoc(t, out).at(t, "connections", "gw1")
	// The IKE-level (Phase 1) proposals line is intentionally absent.
	//
	// #6824: the guard used to be spelled as the four-space-indented
	// "\n    proposals = " to keep it from matching the child section's
	// "        esp_proposals = " line. Asking whether THIS section declares
	// the key removes the dependence on the renderer's indentation, and stays
	// correct if the indent ever changes.
	conn.hasNoSetting(t, "proposals")
	// The child SA still carries its own esp_proposals; the absence above is
	// about Phase 1 only, and this pins that the two are not confused.
	//
	// `len(conn.children) == 0` was VACUOUS here: conn.children holds local,
	// remote AND children, so it is non-empty even when the children{} block
	// carries no child SA at all, and stays non-empty if that block disappears.
	// The claim is about the child SAs, so resolve children{} and count THOSE.
	kids := conn.at(t, "children")
	if len(kids.order) == 0 {
		t.Errorf("no-policy tunnel rendered a children{} block with no child SA:\n%s", kids)
	}
	kids.at(t, kids.order[0]).setting(t, "esp_proposals")
}
