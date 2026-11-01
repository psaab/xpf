package config

import (
	"reflect"
	"testing"
)

// #18787: a two-level packed spelling (`<outer> <inner> <leaf> <value>;`
// beside the rest of the stanza) of these security settings committed clean at
// the STRICT gate but compiled to a weaker config than its braced twin: IPsec
// PFS group 0, a VPN with no ipsec-policy, VPN monitoring off, and
// web-management api-auth and HTTPS gone. Each IPsec row compiles both
// spellings strictly and requires the same compiled section, with a positive
// control that the braced spelling actually sets the value.

func strictCompileText18787(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v\n%s", perrs, text)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile: %v\n%s", err, text)
	}
	return cfg
}

const (
	ifs18787   = `interfaces { ge-0/0/0 { unit 0 { family inet { address 198.51.100.1/24; } } } st0 { unit 0 { family inet; } } fxp0 { unit 0 { family inet { address 192.168.1.1/24; } } } } `
	ike18787   = `ike { proposal p1 { authentication-method pre-shared-keys; dh-group group14; authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; } policy ip1 { mode main; proposals p1; pre-shared-key ascii-text "secret-psk-1234567890"; } gateway gw1 { ike-policy ip1; address 192.0.2.1; external-interface ge-0/0/0.0; } } `
	ipp18787   = `proposal ipp { protocol esp; encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; } `
	zones18787 = `zones { security-zone vpn { interfaces { st0.0; } } security-zone untrust { interfaces { ge-0/0/0.0; } } } `
)

func ipsecText18787(ipsec string) string {
	return ifs18787 + `security { ` + zones18787 + ike18787 + `ipsec { ` + ipp18787 + ipsec + ` } }`
}

// TwoLevelSecurityRows18787 is shared with the pkg/ipsec render cell.
var twoLevelSecurityRows18787 = []struct {
	name, braced, twoLevel string
	set                    func(*Config) bool // positive control on the braced compile
	section                func(*Config) any
}{
	{
		name:     "ipsec policy perfect-forward-secrecy keys",
		braced:   ipsecText18787(`policy ipol { perfect-forward-secrecy { keys group14; } proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } establish-tunnels immediately; }`),
		twoLevel: ipsecText18787(`policy ipol perfect-forward-secrecy keys group14; policy ipol { proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } establish-tunnels immediately; }`),
		set:      func(c *Config) bool { return c.Security.IPsec.Policies["ipol"].PFSGroup == 14 },
		section:  func(c *Config) any { return *c.Security.IPsec.Policies["ipol"] },
	},
	{
		name:     "ipsec vpn ike ipsec-policy",
		braced:   ipsecText18787(`policy ipol { perfect-forward-secrecy { keys group14; } proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } establish-tunnels immediately; }`),
		twoLevel: ipsecText18787(`policy ipol { perfect-forward-secrecy { keys group14; } proposals ipp; } vpn v1 ike ipsec-policy ipol; vpn v1 { bind-interface st0.0; ike { gateway gw1; } establish-tunnels immediately; }`),
		set:      func(c *Config) bool { return c.Security.IPsec.VPNs["v1"].IPsecPolicy == "ipol" },
		section:  func(c *Config) any { return *c.Security.IPsec.VPNs["v1"] },
	},
	{
		name:     "ipsec vpn vpn-monitor",
		braced:   ipsecText18787(`policy ipol { proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } vpn-monitor { destination-ip 192.0.2.1; optimized; source-interface ge-0/0/0.0; } establish-tunnels immediately; }`),
		twoLevel: ipsecText18787(`policy ipol { proposals ipp; } vpn v1 vpn-monitor optimized; vpn v1 vpn-monitor destination-ip 192.0.2.1; vpn v1 vpn-monitor source-interface ge-0/0/0.0; vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } establish-tunnels immediately; }`),
		set: func(c *Config) bool {
			v := c.Security.IPsec.VPNs["v1"]
			return v.VPNMonitorOptimized && v.VPNMonitorDestinationIP == "192.0.2.1" && v.VPNMonitorSourceInterface == "ge-0/0/0.0"
		},
		section: func(c *Config) any { return *c.Security.IPsec.VPNs["v1"] },
	},
}

func TestTwoLevelSecuritySpellingsCompileLikeBraced18787(t *testing.T) {
	for _, r := range twoLevelSecurityRows18787 {
		t.Run(r.name, func(t *testing.T) {
			b := strictCompileText18787(t, r.braced)
			if !r.set(b) {
				t.Fatal("POSITIVE CONTROL: the braced spelling does not set the value, so this row cannot observe a drop")
			}
			e := strictCompileText18787(t, r.twoLevel)
			if !r.set(e) {
				t.Errorf("the two-level spelling committed but the value was DROPPED (#18787)")
			}
			if !reflect.DeepEqual(r.section(b), r.section(e)) {
				t.Errorf("two-level spelling compiled a different section:\n  braced:    %+v\n  two-level: %+v", r.section(b), r.section(e))
			}
		})
	}
}

// The api-auth two-level spelling folds into a SECOND web-management block.
// Two duplicate braced web-management blocks are refused at strict commit
// (the api-auth gate sees a block with no credential), so after #18787 the
// two-level spelling must be refused LOUDLY the same way -- never commit while
// dropping api-auth, metrics-require-auth and HTTPS, as it did before.
func TestTwoLevelAPIAuthNeverCommitsWeaker18787(t *testing.T) {
	braced := `system { services { web-management { https { system-generated-certificate; } api-auth { expires 2099-01-01; user admin { password "correct-horse-battery"; } metrics-require-auth; } } } }`
	b := strictCompileText18787(t, braced)
	if w := b.System.Services.WebManagement; w == nil || !w.HTTPS || w.APIAuth == nil || !w.APIAuth.MetricsRequireAuth {
		t.Fatal("POSITIVE CONTROL: the braced spelling does not compile api-auth + metrics-require-auth + HTTPS")
	}
	for name, text := range map[string]string{
		"two-level":                  `system { services { web-management api-auth metrics-require-auth; web-management { https { system-generated-certificate; } api-auth { expires 2099-01-01; user admin { password "correct-horse-battery"; } } } } }`,
		"duplicate braced (control)": `system { services { web-management { api-auth { metrics-require-auth; } } web-management { https { system-generated-certificate; } api-auth { expires 2099-01-01; user admin { password "correct-horse-battery"; } } } } }`,
	} {
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: parse: %v", name, perrs)
		}
		cfg, err := CompileConfig(tree)
		if err == nil {
			w := cfg.System.Services.WebManagement
			if w == nil || !w.HTTPS || w.APIAuth == nil || !w.APIAuth.MetricsRequireAuth {
				t.Errorf("%s: committed CLEAN while dropping api-auth / metrics-require-auth / HTTPS (#18787): %+v", name, w)
			}
		}
	}
}
