package config

import (
	"strings"
	"testing"
)

// #14139 (D5-06): a PSK-authenticated VPN with no effective secret is
// refused at commit; the tolerant load / peer-sync path warns and keeps
// the VPN (the pkg/ipsec render belt skips it). Pubkey VPNs and VPNs
// whose key comes from the IKE-policy fallback commit cleanly.
func TestIPsecPSKPresence14139(t *testing.T) {
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
	mkIKE := func(authMethod string) []string {
		return []string{
			"set security ike gateway gw address 203.0.113.1",
			"set security ike gateway gw ike-policy pol",
			"set security ike policy pol mode main",
			"set security ike policy pol proposals prop",
			"set security ike proposal prop authentication-method " + authMethod,
			"set security ike proposal prop authentication-algorithm sha-256",
			"set security ike proposal prop encryption-algorithm aes-256-cbc",
			"set security ike proposal prop dh-group group14",
		}
	}

	t.Run("psk vpn with no key anywhere is refused at commit", func(t *testing.T) {
		cmds := append(mkIKE("pre-shared-keys"),
			"set security ipsec vpn v1 ike gateway gw",
			"set security ipsec vpn v1 bind-interface st0.0")
		if _, err := CompileConfig(build(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "no pre-shared key is configured") {
			t.Fatalf("commit must refuse a PSK VPN with no key, got %v", err)
		}
		lenient, err := CompileConfigLenient(build(t, cmds))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec missing pre-shared key") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn about the missing PSK, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["v1"] == nil {
			t.Fatal("tolerant path must keep the VPN (render belt skips it)")
		}
	})

	t.Run("vpn-level key commits", func(t *testing.T) {
		cmds := append(mkIKE("pre-shared-keys"),
			"set security ipsec vpn v1 ike gateway gw",
			"set security ipsec vpn v1 bind-interface st0.0",
			"set security ipsec vpn v1 pre-shared-key vpn-secret")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("commit with a vpn key must pass: %v", err)
		}
	})

	t.Run("ike-policy fallback key commits", func(t *testing.T) {
		cmds := append(mkIKE("pre-shared-keys"),
			"set security ike policy pol pre-shared-key ascii-text policy-secret",
			"set security ipsec vpn v1 ike gateway gw",
			"set security ipsec vpn v1 bind-interface st0.0")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("commit with an ike-policy fallback key must pass: %v", err)
		}
	})

	t.Run("pubkey vpn without a key commits", func(t *testing.T) {
		cmds := append(mkIKE("rsa-signatures"),
			"set security ipsec vpn v1 ike gateway gw",
			"set security ipsec vpn v1 bind-interface st0.0")
		if _, err := CompileConfig(build(t, cmds)); err != nil {
			t.Fatalf("pubkey VPN must commit without a PSK: %v", err)
		}
	})

	t.Run("default-auth vpn (no ike-policy) with no key is refused", func(t *testing.T) {
		cmds := []string{
			"set security ike gateway gw address 203.0.113.1",
			"set security ipsec vpn v1 ike gateway gw",
			"set security ipsec vpn v1 bind-interface st0.0",
		}
		if _, err := CompileConfig(build(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "no pre-shared key is configured") {
			t.Fatalf("commit must refuse a default-PSK VPN with no key, got %v", err)
		}
	})
}
