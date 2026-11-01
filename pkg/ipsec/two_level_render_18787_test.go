package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18787: the two-level packed IPsec spellings must RENDER the same strongSwan
// config as their braced twins. Before the fix `policy ipol perfect-forward-
// secrecy keys group14;` committed clean and rendered esp_proposals with NO
// DH group (PFS off), and `vpn v1 ike ipsec-policy ipol;` rendered the VPN
// without its named ipsec-policy.
func TestTwoLevelIPsecSpellingsRenderLikeBraced18787(t *testing.T) {
	const pre = `interfaces { ge-0/0/0 { unit 0 { family inet { address 198.51.100.1/24; } } } st0 { unit 0 { family inet; } } } ` +
		`security { zones { security-zone vpn { interfaces { st0.0; } } security-zone untrust { interfaces { ge-0/0/0.0; } } } ` +
		`ike { proposal p1 { authentication-method pre-shared-keys; dh-group group14; authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; } policy ip1 { mode main; proposals p1; pre-shared-key ascii-text "secret-psk-1234567890"; } gateway gw1 { ike-policy ip1; address 192.0.2.1; local-address 198.51.100.1; } } ` +
		`ipsec { proposal ipp { protocol esp; encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; } `
	const post = ` } }`
	braced := pre + `policy ipol { perfect-forward-secrecy { keys group14; } proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } traffic-selector ts1 { local-ip 10.1.0.0/24; remote-ip 10.9.0.0/24; } establish-tunnels immediately; }` + post
	render := func(t *testing.T, text string) string {
		t.Helper()
		tree, perrs := config.NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		out, _, err := (&Manager{}).renderConfig(&cfg.Security.IPsec)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		return out
	}
	want := render(t, braced)
	if !strings.Contains(want, "esp_proposals = aes256-sha256-modp2048") {
		t.Fatalf("POSITIVE CONTROL: the braced render does not carry PFS group14 (modp2048) on esp_proposals:\n%s", want)
	}
	for name, text := range map[string]string{
		"policy perfect-forward-secrecy keys": pre + `policy ipol perfect-forward-secrecy keys group14; policy ipol { proposals ipp; } vpn v1 { bind-interface st0.0; ike { gateway gw1; ipsec-policy ipol; } traffic-selector ts1 { local-ip 10.1.0.0/24; remote-ip 10.9.0.0/24; } establish-tunnels immediately; }` + post,
		"vpn ike ipsec-policy":                pre + `policy ipol { perfect-forward-secrecy { keys group14; } proposals ipp; } vpn v1 ike ipsec-policy ipol; vpn v1 { bind-interface st0.0; ike { gateway gw1; } traffic-selector ts1 { local-ip 10.1.0.0/24; remote-ip 10.9.0.0/24; } establish-tunnels immediately; }` + post,
	} {
		if got := render(t, text); got != want {
			t.Errorf("%s: two-level spelling rendered a different strongSwan config (#18787):\n--- braced ---\n%s\n--- two-level ---\n%s", name, want, got)
		}
	}
}
