package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileIPsecLenient10884(t *testing.T, commands []string) *config.IPsecConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return &compiled.Security.IPsec
}

// TestExplicitTrafficSelectorShapeBelt10884 keeps an invalid identity fallback
// out of an explicit child while preserving its valid sibling. If every child
// is unrenderable, renderConfig skips the VPN by name instead of asking charon
// to discard the whole connection.
func TestExplicitTrafficSelectorShapeBelt10884(t *testing.T) {
	t.Run("valid sibling child loads", func(t *testing.T) {
		cfg := &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
			"mixed": {
				Name:     "mixed",
				Gateway:  "192.0.2.10",
				LocalID:  "vpn.example.com",
				RemoteID: "peer.example.com",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"bad":  {Name: "bad", RemoteIP: "10.20.0.0/24"},
					"good": {Name: "good", LocalIP: "10.10.0.0/24", RemoteIP: "10.20.1.0/24"},
				},
			},
		}}

		doc := parseSwanctlDoc(t, (&Manager{}).generateConfig(cfg))
		children := doc.at(t, "connections", "mixed", "children")
		got := children.childNames()
		if len(got) != 1 || got[0] != "mixed-good" {
			t.Fatalf("rendered children = %v, want only valid sibling mixed-good", got)
		}
		children.hasNoChild(t, "mixed-bad")
		children.at(t, "mixed-good").requireSetting(t, "local_ts", "10.10.0.0/24")
	})

	t.Run("lenient all-invalid VPN skips by name", func(t *testing.T) {
		cfg := compileIPsecLenient10884(t, []string{
			"set security ipsec vpn unrenderable gateway 192.0.2.20",
			"set security ipsec vpn unrenderable local-identity vpn.example.com",
			"set security ipsec vpn unrenderable remote-identity peer.example.com",
			"set security ipsec vpn unrenderable traffic-selector alpha remote-ip 10.30.0.0/24",
			"set security ipsec vpn unrenderable traffic-selector beta local-ip 10.30.1.0/24",
			"set security ipsec vpn healthy gateway 192.0.2.30",
			"set security ipsec vpn healthy traffic-selector site local-ip 10.40.0.0/24",
			"set security ipsec vpn healthy traffic-selector site remote-ip 10.50.0.0/24",
		})
		bad := cfg.VPNs["unrenderable"]
		if bad == nil || bad.LocalID != "vpn.example.com" || len(bad.TrafficSelectors) != 2 {
			t.Fatalf("lenient compiler did not retain the identity-fallback fixture: %+v", bad)
		}

		text, rendered, err := (&Manager{}).renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig returned error: %v", err)
		}
		if rendered["unrenderable"] {
			t.Fatal("VPN with only FQDN identity fallbacks was rendered; want skip-by-name")
		}
		if !rendered["healthy"] {
			t.Fatalf("healthy VPN was skipped with unrenderable sibling: %s", text)
		}
		doc := parseSwanctlDoc(t, text)
		connections := doc.at(t, "connections")
		connections.hasNoChild(t, "unrenderable")
		connections.at(t, "healthy", "children").at(t, "healthy-site").
			requireSetting(t, "local_ts", "10.40.0.0/24")
	})

	t.Run("selector-shaped identity fallback remains valid", func(t *testing.T) {
		cfg := &config.IPsecConfig{VPNs: map[string]*config.IPsecVPN{
			"fallback": {
				Name:    "fallback",
				Gateway: "192.0.2.40",
				LocalID: "10.60.0.0/24",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"remote-only": {Name: "remote-only", RemoteIP: "10.70.0.0/24"},
				},
			},
		}}

		child := parseSwanctlDoc(t, (&Manager{}).generateConfig(cfg)).
			at(t, "connections", "fallback", "children", "fallback-remote-only")
		child.requireSetting(t, "local_ts", "10.60.0.0/24")
		child.requireSetting(t, "remote_ts", "10.70.0.0/24")
	})
}
