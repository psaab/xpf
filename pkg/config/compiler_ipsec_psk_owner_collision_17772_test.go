package config

import (
	"strings"
	"testing"
)

// #17772: peer-only PSK selectors were deduplicated only per connection.
// Distinct connections could share an explicit remote identity with
// different PSKs, A's remote identity could equal B's local identity, and
// a mixed hostname/IP gateway without a discriminating remote identity
// kept a hostname dial target no rendered selector can authenticate.
// Strict commit must reject those shapes (tolerant paths warn and keep
// the VPNs; the pkg/ipsec render belt skips the colliding connections).
// Controls: distinct identities, an explicit remote identity on a mixed
// gateway, two VPNs sharing one gateway, and the same identity with the
// SAME PSK across gateways (an identical duplicate secret, not a
// collision between different credentials).

func buildTree17772(t *testing.T, commands []string) *ConfigTree {
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

func base17772() []string {
	return []string{
		"set security ike proposal p1 authentication-method pre-shared-keys",
		"set security ike proposal p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal p1 authentication-algorithm sha-256",
		"set security ike proposal p1 dh-group group14",
		"set security ike policy ike-pol proposals p1",
		"set security ike policy ike-pol pre-shared-key ascii-text policy-secret",
	}
}

func twoVPN17772(gwA, gwB []string, pskA, pskB string) []string {
	cmds := base17772()
	cmds = append(cmds, gwA...)
	cmds = append(cmds, gwB...)
	cmds = append(cmds,
		"set security ipsec vpn vpn-a ike gateway gw-a",
		"set security ipsec vpn vpn-a bind-interface st0.0",
		"set security ipsec vpn vpn-b ike gateway gw-b",
		"set security ipsec vpn vpn-b bind-interface st0.1")
	if pskA != "" {
		cmds = append(cmds, "set security ipsec vpn vpn-a pre-shared-key ascii-text "+pskA)
	}
	if pskB != "" {
		cmds = append(cmds, "set security ipsec vpn vpn-b pre-shared-key ascii-text "+pskB)
	}
	return cmds
}

func TestIPsecPSKOwnerCollision17772(t *testing.T) {
	t.Run("shared explicit remote identity across distinct gateways with distinct PSKs is refused", func(t *testing.T) {
		cmds := twoVPN17772([]string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address 203.0.113.1",
			"set security ike gateway gw-a remote-identity hostname shared.example.com",
		}, []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address 203.0.113.2",
			"set security ike gateway gw-b remote-identity hostname shared.example.com",
		}, "secret-a", "secret-b")
		_, err := CompileConfig(buildTree17772(t, cmds))
		if err == nil || !strings.Contains(err.Error(), "#17772") ||
			!strings.Contains(err.Error(), "gw-a") || !strings.Contains(err.Error(), "gw-b") ||
			!strings.Contains(err.Error(), "shared.example.com") {
			t.Fatalf("commit must refuse a shared remote identity with distinct PSKs naming both gateways and #17772, got %v", err)
		}
		if strings.Contains(err.Error(), "secret-a") || strings.Contains(err.Error(), "secret-b") {
			t.Fatalf("error must never leak PSK material: %v", err)
		}
		lenient, err := CompileConfigLenient(buildTree17772(t, cmds))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "#17772") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn with #17772, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["vpn-a"] == nil || lenient.Security.IPsec.VPNs["vpn-b"] == nil {
			t.Fatal("tolerant path must keep both VPNs (render belt skips them)")
		}
	})

	t.Run("same gateway address across distinct gateways with distinct PSKs is refused", func(t *testing.T) {
		cmds := twoVPN17772([]string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address 203.0.113.1",
		}, []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address 203.0.113.1",
		}, "secret-a", "secret-b")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err == nil ||
			!strings.Contains(err.Error(), "#17772") {
			t.Fatalf("commit must refuse the same peer address scoping distinct PSKs (#17772), got %v", err)
		}
	})

	t.Run("A remote identity equal to B local identity is refused", func(t *testing.T) {
		cmds := twoVPN17772([]string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address 203.0.113.1",
			"set security ike gateway gw-a remote-identity hostname shared.example.com",
		}, []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address 203.0.113.2",
			"set security ike gateway gw-b local-identity hostname shared.example.com",
		}, "secret-a", "secret-b")
		_, err := CompileConfig(buildTree17772(t, cmds))
		if err == nil || !strings.Contains(err.Error(), "#17772") ||
			!strings.Contains(err.Error(), "gw-a") || !strings.Contains(err.Error(), "gw-b") {
			t.Fatalf("commit must refuse A-remote == B-local across connections naming both gateways and #17772, got %v", err)
		}
		if strings.Contains(err.Error(), "secret-a") || strings.Contains(err.Error(), "secret-b") {
			t.Fatalf("error must never leak PSK material: %v", err)
		}
	})

	t.Run("mixed hostname and IP gateway without explicit remote identity is refused", func(t *testing.T) {
		cmds := append(base17772(),
			"set security ike gateway mix-gw ike-policy ike-pol",
			"set security ike gateway mix-gw address peer.example.test",
			"set security ike gateway mix-gw address 203.0.113.1",
			"set security ipsec vpn site ike gateway mix-gw",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")
		_, err := CompileConfig(buildTree17772(t, cmds))
		if err == nil || !strings.Contains(err.Error(), "#17772") ||
			!strings.Contains(err.Error(), "peer.example.test") {
			t.Fatalf("commit must refuse a mixed hostname/IP gateway with no discriminating remote identity naming the hostname and #17772, got %v", err)
		}
		lenient, err := CompileConfigLenient(buildTree17772(t, cmds))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "#17772") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn with #17772, warnings=%v", lenient.Warnings)
		}
	})

	t.Run("distinct explicit identities with distinct PSKs commit", func(t *testing.T) {
		cmds := twoVPN17772([]string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address 203.0.113.1",
			"set security ike gateway gw-a remote-identity hostname a.example.com",
		}, []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address 203.0.113.2",
			"set security ike gateway gw-b remote-identity hostname b.example.com",
		}, "secret-a", "secret-b")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err != nil {
			t.Fatalf("distinct identities must commit: %v", err)
		}
	})

	t.Run("mixed hostname and IP gateway with explicit remote identity commits", func(t *testing.T) {
		cmds := append(base17772(),
			"set security ike gateway mix-gw ike-policy ike-pol",
			"set security ike gateway mix-gw address peer.example.test",
			"set security ike gateway mix-gw address 203.0.113.1",
			"set security ike gateway mix-gw remote-identity hostname peer.example.test",
			"set security ipsec vpn site ike gateway mix-gw",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err != nil {
			t.Fatalf("mixed gateway with an explicit remote identity must commit: %v", err)
		}
	})

	t.Run("same identity with the same PSK across distinct gateways commits", func(t *testing.T) {
		cmds := twoVPN17772([]string{
			"set security ike gateway gw-a ike-policy ike-pol",
			"set security ike gateway gw-a address 203.0.113.1",
			"set security ike gateway gw-a remote-identity hostname shared.example.com",
		}, []string{
			"set security ike gateway gw-b ike-policy ike-pol",
			"set security ike gateway gw-b address 203.0.113.2",
			"set security ike gateway gw-b remote-identity hostname shared.example.com",
		}, "same-secret", "same-secret")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err != nil {
			t.Fatalf("identical PSK under an identical identity is a duplicate, not a collision: %v", err)
		}
	})

	t.Run("two VPNs sharing one gateway commit", func(t *testing.T) {
		cmds := append(base17772(),
			"set security ike gateway gw-shared ike-policy ike-pol",
			"set security ike gateway gw-shared address 203.0.113.1",
			"set security ike gateway gw-shared remote-identity hostname shared.example.com",
			"set security ipsec vpn vpn-a ike gateway gw-shared",
			"set security ipsec vpn vpn-a bind-interface st0.0",
			"set security ipsec vpn vpn-b ike gateway gw-shared",
			"set security ipsec vpn vpn-b bind-interface st0.1")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err != nil {
			t.Fatalf("VPNs sharing one gateway connection must commit: %v", err)
		}
	})

	t.Run("own remote identity equal to own local identity commits", func(t *testing.T) {
		cmds := append(base17772(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw address 203.0.113.1",
			"set security ike gateway gw remote-identity hostname self.example.com",
			"set security ike gateway gw local-identity hostname self.example.com",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")
		if _, err := CompileConfig(buildTree17772(t, cmds)); err != nil {
			t.Fatalf("a single connection whose remote identity equals its own local identity must commit: %v", err)
		}
	})
}
