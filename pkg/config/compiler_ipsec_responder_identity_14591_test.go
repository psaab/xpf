package config

import (
	"strings"
	"testing"
)

// #14591 (Y09-04): a responder-only (`dynamic`) gateway used by a VPN must
// carry a remote-identity. Without one the responder-only PSK secret cannot
// be scoped to a peer identity, so a holder of another VPN's PSK can
// authenticate into it by claiming that site's identity. Commit refuses;
// the tolerant load / peer-sync path warns and keeps the VPN (the
// pkg/ipsec render belt skips the unscoped connection).
func TestIPsecResponderIdentity14591(t *testing.T) {
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
	// mkCmds builds a responder-only gateway + VPN. extra carries the
	// optional remote-identity / auth variation under test.
	mkCmds := func(extra ...string) []string {
		cmds := []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike policy ike-pol pre-shared-key ascii-text rw-secret",
			"set security ike gateway rw-gw ike-policy ike-pol",
			"set security ike gateway rw-gw local-address 198.51.100.1",
			"set security ike gateway rw-gw dynamic",
			"set security ipsec vpn rw ike gateway rw-gw",
			"set security ipsec vpn rw bind-interface st0.1",
		}
		return append(cmds, extra...)
	}

	t.Run("responder-only gateway without remote-identity is refused at commit", func(t *testing.T) {
		if _, err := CompileConfig(build(t, mkCmds())); err == nil ||
			!strings.Contains(err.Error(), "remote-identity") {
			t.Fatalf("commit must refuse a responder-only gateway with no remote-identity, got %v", err)
		}
		lenient, err := CompileConfigLenient(build(t, mkCmds()))
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
			t.Fatalf("tolerant path must warn about the missing remote-identity, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["rw"] == nil {
			t.Fatal("tolerant path must keep the VPN (render belt skips it)")
		}
	})

	t.Run("responder-only gateway with remote-identity commits", func(t *testing.T) {
		cmds := mkCmds("set security ike gateway rw-gw remote-identity hostname rw.example.com")
		cfg, err := CompileConfig(build(t, cmds))
		if err != nil {
			t.Fatalf("commit with a remote-identity must pass: %v", err)
		}
		gw := cfg.Security.IPsec.Gateways["rw-gw"]
		if gw == nil || !gw.ResponderOnly || gw.RemoteIDValue != "rw.example.com" {
			t.Fatalf("gateway = %+v, want responder-only with remote-id rw.example.com", gw)
		}
	})

	t.Run("fixed-address gateway without remote-identity still commits", func(t *testing.T) {
		// Control: only responder-only gateways need the identity — a
		// fixed peer is already scoped by its gateway address.
		cmds := []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike policy ike-pol pre-shared-key ascii-text site-secret",
			"set security ike gateway site-gw ike-policy ike-pol",
			"set security ike gateway site-gw address 203.0.113.1",
			"set security ipsec vpn site ike gateway site-gw",
			"set security ipsec vpn site bind-interface st0.0",
		}
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("fixed-address gateway without remote-identity must commit: %v", err)
		}
	})
}
