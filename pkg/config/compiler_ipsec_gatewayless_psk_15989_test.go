package config

import (
	"strings"
	"testing"
)

// #15989 (H-4): a gateway-less PSK VPN (no `ike gateway` leaf, e.g. a
// route-based st0.0 VPN with only a pre-shared-key) has no peer address
// or identity to scope its secret to. Pre-fix it evaded every #14591-era
// gate — the responder-identity lookup of "" misses, the
// gateway-references gate continues on empty gateway, and the render
// belt's responderOnlyGateway(nil) is false — and rendered a lone
// id-1 = "%any" secret matching any peer identity, so a holder of any
// on-box PSK could authenticate into the tunnel. Strict commit must
// reject it; the tolerant load / peer-sync path downgrades to the same
// #14591 warning prefix and keeps the VPN (the pkg/ipsec render belt skips it,
// pinned in pkg/ipsec TestGatewaylessPSK15989). #16708 requires an inline
// hostname to use an IKE gateway object carrying remote-identity; an inline IP
// literal remains a valid peer scope.
func TestGatewaylessPSK15989(t *testing.T) {
	build := func(t *testing.T, commands []string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, command := range commands {
			path, err := ParseSetCommand(command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", command, err)
			}
		}
		return tree
	}
	gatewayless := []string{
		"set security ipsec vpn gwless bind-interface st0.0",
		"set security ipsec vpn gwless pre-shared-key ascii-text gwless-secret",
	}

	t.Run("route-based gateway-less PSK VPN is refused at commit", func(t *testing.T) {
		if _, err := CompileConfig(build(t, gatewayless)); err == nil ||
			!strings.Contains(err.Error(), "no ike gateway") {
			t.Fatalf("commit must refuse a gateway-less PSK VPN (#15989), got %v", err)
		}
	})

	t.Run("tolerant path warns and keeps the VPN", func(t *testing.T) {
		lenient, err := CompileConfigLenient(build(t, gatewayless))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec responder-only remote identity") &&
				strings.Contains(w, "no ike gateway") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn about the gateway-less PSK VPN, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["gwless"] == nil {
			t.Fatal("tolerant path must keep the VPN (render belt skips it)")
		}
	})

	t.Run("inline IP endpoint PSK VPN still commits", func(t *testing.T) {
		cmds := []string{
			"set security ipsec vpn tun gateway 192.0.2.1",
			"set security ipsec vpn tun bind-interface st0.0",
			"set security ipsec vpn tun pre-shared-key ascii-text inline-secret",
		}
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("inline IP endpoint PSK VPN must commit (#15989 control), got: %v", err)
		}
	})

	t.Run("inline hostname endpoint is refused without a gateway remote identity", func(t *testing.T) {
		cmds := []string{
			"set security ipsec vpn tun gateway peer.example.com",
			"set security ipsec vpn tun bind-interface st0.0",
			"set security ipsec vpn tun pre-shared-key ascii-text inline-secret",
		}
		if _, err := CompileConfig(build(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "#16708") {
			t.Fatalf("inline hostname PSK endpoint must be refused (#16708), got: %v", err)
		}
	})
}
