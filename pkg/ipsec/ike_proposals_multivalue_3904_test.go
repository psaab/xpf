package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3904 (fable-161 F-040/F-161): a multi-proposal IKE/IPsec policy
// (`proposals [ p1 p2 ]`) must offer EVERY listed proposal in the generated
// swanctl config. Before #3904 IKEPolicy.Proposals / IPsecPolicyDef.Proposals
// were scalar strings that captured only the first reference, so phase-1/2
// negotiation silently narrowed — a peer requiring the second proposal could
// not establish. resolveIKESettings / resolveESPSettings now build every
// resolvable reference and comma-join them into the swanctl proposals list.
//
// fail-on-revert: restoring the scalar (single-proposal) render drops the
// second proposal from both the `proposals =` (IKE) and `esp_proposals =`
// (ESP) lines, so the "second proposal present" assertions go RED.

// TestGenerateConfig_MultiIKEProposals asserts both IKE proposals in a
// `proposals [ ike-a ike-b ]` policy reach the swanctl `proposals =` line,
// comma-joined and in order.
func TestGenerateConfig_MultiIKEProposals(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {PSK: "fixture-secret", Gateway: "gw1", IPsecPolicy: "esp-pol"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "172.16.0.1", IKEPolicy: "ike-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-a", "ike-b"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-a": {Name: "ike-a", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"ike-b": {Name: "ike-b", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 5},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-a"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: 14},
		},
	}
	// #6824: equality at connections.tun1.proposals subsumes both old checks.
	// The second needle existed because containment on the joined string could
	// not say the join was the WHOLE value -- an exact match at a known path
	// says it, and additionally rejects a third proposal silently appearing.
	parseSwanctlDoc(t, m.generateConfig(cfg)).
		at(t, "connections", "tun1").
		requireSetting(t, "proposals", "aes256-sha256-modp2048,aes128-sha256-modp1536")
}

// TestGenerateConfig_MultiESPProposals asserts both ESP proposals in a
// `proposals [ esp-a esp-b ]` IPsec policy reach the `esp_proposals =` line.
func TestGenerateConfig_MultiESPProposals(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {PSK: "fixture-secret", Gateway: "172.16.0.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: 14},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-256", DHGroup: 5},
		},
	}
	// #6824: the ESP proposals belong to the CHILD SA, not the connection --
	// a distinction containment could not draw.
	childSA_3904(t, m.generateConfig(cfg), "tun1").
		requireSetting(t, "esp_proposals", "aes256-sha256-modp2048,aes128-sha256-modp1536")
}

// TestGenerateConfig_MultiESPProposalsPFS asserts the policy-level PFS group
// is applied to EVERY proposal in the list (the DH suffix is the PFS group,
// not each proposal's own dh-group).
func TestGenerateConfig_MultiESPProposalsPFS(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {PSK: "fixture-secret", Gateway: "172.16.0.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", PFSGroup: 19, Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256"},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-256"},
		},
	}
	childSA_3904(t, m.generateConfig(cfg), "tun1").
		requireSetting(t, "esp_proposals", "aes256-sha256-ecp256,aes128-sha256-ecp256")
}

// childSA_3904 resolves the single child-SA section of a connection, failing if
// the render produced anything other than exactly one. "Exactly one" is itself
// part of the claim: a second child section would carry its own esp_proposals,
// and a containment assertion could not tell which one it had matched.
func childSA_3904(t *testing.T, doc, conn string) *swanctlNode {
	t.Helper()
	kids := parseSwanctlDoc(t, doc).at(t, "connections", conn, "children")
	if len(kids.order) != 1 {
		t.Fatalf("connection %q rendered %d child SA sections (%v), want exactly 1\n%s",
			conn, len(kids.order), kids.childNames(), kids)
	}
	return kids.at(t, kids.order[0])
}
