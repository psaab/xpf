package config

import (
	"strings"
	"testing"
)

// #16708: a PSK VPN whose gateway is addressed only by hostname (or an
// inline hostname endpoint) with no remote-identity has no peer identity
// to scope its secret by — the hostname is a dial target, never the
// identity the peer presents (#16680). Pre-#16708 the secret carried only
// the box-shared local owner, which every peer matches. Commit refuses
// the shape (the tolerant path warns and the render belt skips it);
// a remote-identity, an IP literal, or a mixed hostname+IP list commits.
func TestIPsecHostnameIdentity16708(t *testing.T) {
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
	base := func(gwCmds []string, vpnGateway string) []string {
		cmds := []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike policy ike-pol pre-shared-key ascii-text site-secret",
		}
		cmds = append(cmds, gwCmds...)
		return append(cmds,
			"set security ipsec vpn site ike gateway "+vpnGateway,
			"set security ipsec vpn site bind-interface st0.0")
	}

	t.Run("hostname gateway without remote-identity is refused at commit", func(t *testing.T) {
		cmds := base([]string{
			"set security ike gateway host-gw ike-policy ike-pol",
			"set security ike gateway host-gw address peer.example.test",
		}, "host-gw")
		if _, err := CompileConfig(build(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "remote-identity") ||
			!strings.Contains(err.Error(), "#16708") {
			t.Fatalf("commit must refuse a hostname gateway with no remote-identity (#16708), got %v", err)
		}
		lenient, err := CompileConfigLenient(build(t, cmds))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec responder-only remote identity") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["site"] == nil {
			t.Fatal("tolerant path must keep the VPN (render belt skips it)")
		}
	})

	t.Run("hostname gateway with remote-identity commits", func(t *testing.T) {
		cmds := base([]string{
			"set security ike gateway host-gw ike-policy ike-pol",
			"set security ike gateway host-gw address peer.example.test",
			"set security ike gateway host-gw remote-identity hostname peer.example.test",
		}, "host-gw")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("hostname gateway with remote-identity must commit: %v", err)
		}
	})

	t.Run("mixed hostname and IP gateway commits", func(t *testing.T) {
		cmds := base([]string{
			"set security ike gateway mix-gw ike-policy ike-pol",
			"set security ike gateway mix-gw address peer.example.test",
			"set security ike gateway mix-gw address 203.0.113.1",
		}, "mix-gw")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("mixed hostname+IP gateway must commit (IP scopes the secret): %v", err)
		}
	})

	t.Run("inline hostname endpoint is refused at commit", func(t *testing.T) {
		cmds := append(base(nil, "peer.example.test"),
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")
		if _, err := CompileConfig(build(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "#16708") {
			t.Fatalf("commit must refuse an inline hostname endpoint (#16708), got %v", err)
		}
	})

	t.Run("inline IP endpoint commits (control)", func(t *testing.T) {
		cmds := append(base(nil, "203.0.113.1"),
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("inline IP endpoint must commit: %v", err)
		}
	})

	t.Run("pubkey hostname gateway is not refused", func(t *testing.T) {
		cmds := []string{
			"set security ike proposal p1 authentication-method rsa-signatures",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike gateway cert-gw ike-policy ike-pol",
			"set security ike gateway cert-gw address peer.example.test",
			"set security ike gateway cert-gw local-certificate fw-cert",
			"set security ipsec vpn site ike gateway cert-gw",
			"set security ipsec vpn site bind-interface st0.0",
		}
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("pubkey hostname gateway must commit (no PSK to scope): %v", err)
		}
	})
}
