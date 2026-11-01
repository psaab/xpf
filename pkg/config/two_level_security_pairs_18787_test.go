package config

import (
	"reflect"
	"strings"
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

// The api-auth two-level spelling folds into a SECOND web-management block,
// and the compiler read web-management with FindChild, so whichever block came
// second was dropped on a clean commit: api-auth when the packed line followed
// the braced stanza, HTTPS when it preceded it. Two duplicate braced blocks
// lost the same way. Every row must strict-commit and compile the SAME
// WebManagementConfig as the one-block reference, in both orders.
func TestWebManagementSiblingsCompileLikeBraced18787(t *testing.T) {
	const (
		user  = `user admin { password "correct-horse-battery"; }`
		auth  = `api-auth { expires 2099-01-01; ` + user + ` metrics-require-auth; } `
		https = `https { system-generated-certificate; interface fxp0.0; } `
	)
	// User passwords are bcrypt-hashed at compile with a random salt, so two
	// compiles of one password never compare equal. Replace each hash with a
	// marker only after checking it IS a hash, so a dropped password still
	// shows as a difference.
	wm := func(t *testing.T, text string) *WebManagementConfig {
		t.Helper()
		w := strictCompileText18787(t, `system { services { `+text+` } }`).System.Services.WebManagement
		if w != nil && w.APIAuth != nil {
			for _, u := range w.APIAuth.Users {
				if strings.HasPrefix(u.Password.Reveal(), "$xpf-bcrypt$") {
					u.Password = NewSecret("<bcrypt>")
				}
			}
		}
		return w
	}
	refAuth := wm(t, `web-management { `+https+auth+`}`)
	if refAuth == nil || !refAuth.HTTPS || refAuth.HTTPSInterface != "fxp0.0" || !refAuth.SystemGeneratedCert ||
		refAuth.APIAuth == nil || !refAuth.APIAuth.MetricsRequireAuth || len(refAuth.APIAuth.Users) != 1 || refAuth.APIAuth.DefaultExpiresAt.IsZero() {
		t.Fatalf("POSITIVE CONTROL: the one-block api-auth reference does not compile every field this cell compares: %+v", refAuth)
	}
	for _, r := range []struct {
		name, text string
		ref        *WebManagementConfig
	}{
		// `api-auth expires` / `api-auth class` stay braced: their own
		// (api-auth, leaf) level is not admitted (open under #11544, and
		// both fail safe -- read-only class, refused immortal credential).
		{"two-level api-auth BEFORE the braced block", `web-management api-auth metrics-require-auth; web-management { ` + https + `api-auth { expires 2099-01-01; ` + user + ` } }`, refAuth},
		{"two-level api-auth AFTER the braced block", `web-management { ` + https + `api-auth { expires 2099-01-01; ` + user + ` } } web-management api-auth metrics-require-auth;`, refAuth},
		{"duplicate braced, api-auth first", `web-management { ` + auth + `} web-management { ` + https + `}`, refAuth},
		{"duplicate braced, api-auth last", `web-management { ` + https + `} web-management { ` + auth + `}`, refAuth},
		{"sibling https blocks", `web-management { https { system-generated-certificate; } https { interface fxp0.0; } ` + auth + `}`, refAuth},
	} {
		t.Run(r.name, func(t *testing.T) {
			got := wm(t, r.text)
			if !reflect.DeepEqual(r.ref, got) {
				t.Errorf("compiled a different web-management than the one-block reference (a sibling block was dropped):\n  want: %+v\n  got:  %+v", r.ref, got)
				if got != nil && r.ref.APIAuth != nil && got.APIAuth != nil {
					t.Logf("api-auth want %+v got %+v", *r.ref.APIAuth, *got.APIAuth)
				}
			}
		})
	}
}

// An http interface never strict-commits: with api-auth HTTP is refused as
// cleartext (#10826), without it the off-loopback bind is refused (#4047). So
// the http sibling read is observable only on the TOLERANT load path, which
// still installs what it loaded.
func TestWebManagementHTTPSiblingsMergeOnTolerantLoad18787(t *testing.T) {
	lenient := func(t *testing.T, text string) *WebManagementConfig {
		t.Helper()
		tree, perrs := NewParser(`system { services { ` + text + ` } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		return cfg.System.Services.WebManagement
	}
	ref := lenient(t, `web-management { http { interface fxp0.0; } }`)
	if ref == nil || !ref.HTTP || ref.HTTPInterface != "fxp0.0" {
		t.Fatalf("POSITIVE CONTROL: the one-block tolerant load does not keep the http interface: %+v", ref)
	}
	for name, text := range map[string]string{
		"sibling http blocks":             `web-management { http; http { interface fxp0.0; } }`,
		"duplicate braced web-management": `web-management { http; } web-management { http { interface fxp0.0; } }`,
	} {
		if got := lenient(t, text); !reflect.DeepEqual(ref, got) {
			t.Errorf("%s: tolerant load dropped a sibling http block:\n  want: %+v\n  got:  %+v", name, ref, got)
		}
	}
}
