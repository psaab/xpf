package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateConfigClampsExtremeRekeyTime10882(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc",
				AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 315360000,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-p1"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {
				Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128",
				DHGroup: 14, LifetimeSeconds: 315360000,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}, PFSGroup: 14},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
	}

	// Characterize the render policy for a legacy/direct value above Junos's
	// range: preserve rekeying but cap it at 86400 seconds instead of emitting
	// the effectively immortal value or discarding the rekey_time setting.
	out := m.generateConfig(cfg)
	doc := parseSwanctlDoc(t, out)
	doc.at(t, "connections", "tun").requireSetting(t, "rekey_time", "86400s")
	childSA_3904(t, out, "tun").requireSetting(t, "rekey_time", "86400s")
}

func TestGenerateConfigTolerantDPDClampsBeforeTimeout10882(t *testing.T) {
	commands := []string{
		`set security ike proposal ike-p1 authentication-method pre-shared-keys`,
		`set security ike proposal ike-p1 dh-group group14`,
		`set security ike proposal ike-p1 encryption-algorithm aes-256-cbc`,
		`set security ike policy pol1 mode main`,
		`set security ike policy pol1 proposals ike-p1`,
		`set security ike policy pol1 pre-shared-key ascii-text mysecret`,
		`set security ike gateway gw1 ike-policy pol1`,
		`set security ike gateway gw1 address 203.0.113.1`,
		`set security ike gateway gw1 dead-peer-detection interval 999999999`,
		`set security ike gateway gw1 dead-peer-detection threshold 999999999`,
		`set security ipsec proposal esp-p2 protocol esp`,
		`set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc`,
		`set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128`,
		`set security ipsec policy ipsec-pol proposals esp-p2`,
		`set security ipsec vpn tun1 bind-interface st0.0`,
		`set security ipsec vpn tun1 ike gateway gw1`,
		`set security ipsec vpn tun1 ike ipsec-policy ipsec-pol`,
	}
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	gw := compiled.Security.IPsec.Gateways["gw1"]
	if gw == nil {
		t.Fatal("tolerant compile dropped gateway gw1")
	}
	if gw.DPDInterval != config.MaxIPsecDPDIntervalSeconds || gw.DPDThreshold != config.MaxIPsecDPDThreshold {
		t.Fatalf("tolerant DPD values = (%d, %d), want clamped (%d, %d)",
			gw.DPDInterval, gw.DPDThreshold,
			config.MaxIPsecDPDIntervalSeconds, config.MaxIPsecDPDThreshold)
	}

	out := (&Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}).generateConfig(&compiled.Security.IPsec)
	conn := parseSwanctlDoc(t, out).at(t, "connections", "tun1")
	conn.requireSetting(t, "dpd_delay", "3600s")
	conn.requireSetting(t, "dpd_timeout", "360000s")
}
