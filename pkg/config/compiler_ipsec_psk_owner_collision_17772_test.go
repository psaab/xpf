package config

import (
	"fmt"
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

func identityPair17772(aType, aValue, bType, bValue string, gatewayBExtras ...string) []string {
	gwA := []string{
		"set security ike gateway gw-a ike-policy ike-pol",
		"set security ike gateway gw-a address 203.0.113.1",
		fmt.Sprintf("set security ike gateway gw-a remote-identity %s %q", aType, aValue),
	}
	gwB := []string{
		"set security ike gateway gw-b ike-policy ike-pol",
		"set security ike gateway gw-b address 203.0.113.2",
		fmt.Sprintf("set security ike gateway gw-b remote-identity %s %q", bType, bValue),
	}
	gwB = append(gwB, gatewayBExtras...)
	return twoVPN17772(gwA, gwB, "secret-a", "secret-b")
}

func requireCollision17772(t *testing.T, commands []string) {
	t.Helper()
	_, err := CompileConfig(buildTree17772(t, commands))
	if err == nil || !strings.Contains(err.Error(), "#17772") {
		t.Fatalf("expected #17772 identity collision, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-a") || strings.Contains(err.Error(), "secret-b") {
		t.Fatalf("collision diagnostics must never disclose PSK material: %v", err)
	}
}

func requireNoCollision17772(t *testing.T, commands []string) {
	t.Helper()
	if _, err := CompileConfig(buildTree17772(t, commands)); err != nil {
		t.Fatalf("distinct identity namespaces/values must commit: %v", err)
	}
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

	t.Run("DN canonical spellings collide", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"separator spacing and case", "CN=peer, O=Org", "cn=PEER,o=ORG"},
			{"RDN order", "CN=peer,O=Org", "O=ORG,CN=PEER"},
			{"multi-valued RDN order", "CN=peer+OU=VPN,O=Org", "OU=vpn+CN=PEER,O=ORG"},
			{"escaped separator", "CN=peer\\,east,O=Org", "O=ORG,CN=PEER\\,EAST"},
			{"case-ignore whitespace", "CN=Peer   Name,O=Org", "cn=peer name,o=org"},
			{"Unicode full case fold", "CN=Straße,O=Org", "cn=STRASSE,o=org"},
		}
		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				requireCollision17772(t, identityPair17772("distinguished-name", pair.a, "distinguished-name", pair.b))
			})
		}
	})

	t.Run("malformed DN escape falls back to raw identity", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("distinguished-name", "CN=peer\\", "distinguished-name", "cn=PEER"))
	})

	t.Run("RFC822 and FQDN namespaces stay distinct", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("email", "peer@corp.example", "hostname", "peer@corp.example"))
	})

	t.Run("DN and FQDN namespaces stay distinct", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("distinguished-name", "CN=peer.example.com", "hostname", "peer.example.com"))
	})

	t.Run("key-id spellings compare strongSwan identity bytes", func(t *testing.T) {
		pairs := []struct{ name, a, b string }{
			{"literal bytes and equivalent hex", "zz", "7a7a"},
			{"hex digits are case-insensitive", "7a7a", "7A7A"},
			{"odd-length input is literal bytes", "7a7", "376137"},
		}
		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				requireCollision17772(t, identityPair17772("key-id", pair.a, "key-id", pair.b))
			})
		}
		requireNoCollision17772(t, identityPair17772("key-id", " 6162 ", "key-id", "6162"))
	})

	t.Run("RFC822 aliases and case-folded domains share one namespace", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"user-at-hostname and rfc822", "user-at-hostname", "peer@corp.example", "rfc822", "peer@CORP.EXAMPLE"},
			{"email and user-at-hostname", "email", "peer@corp.example", "user-at-hostname", "peer@Corp.Example"},
			{"email and rfc822", "email", "peer@corp.example", "rfc822", "peer@CORP.EXAMPLE"},
			{"rfc822 domain case", "rfc822", "peer@corp.example", "rfc822", "peer@CORP.EXAMPLE"},
		}
		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				requireCollision17772(t, identityPair17772(pair.aType, pair.a, pair.bType, pair.b))
			})
		}
	})

	t.Run("RFC822 local part remains case-sensitive", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("user-at-hostname", "Peer@corp.example", "rfc822", "peer@CORP.EXAMPLE"))
	})

	t.Run("cross-type rendered-identical owners collide", func(t *testing.T) {
		pairs := []struct{ name, aType, a, bType, b string }{
			{"inet and inet6 same value", "inet", "198.51.100.7", "inet6", "198.51.100.7"},
			{"inet and email same user-at-host", "inet", "peer@corp.example", "email", "peer@corp.example"},
			{"inet and DN same string", "inet", "CN=peer", "distinguished-name", "CN=peer"},
			{"email and DN same string", "email", "CN=peer", "distinguished-name", "CN=peer"},
			{"inet and email same IP string", "inet", "198.51.100.7", "email", "198.51.100.7"},
			{"hostname adorned equals inet literal @fqdn", "hostname", "peer.example", "inet", "@peer.example"},
			{"key-id rendered equals inet literal @#zz", "key-id", "zz", "inet", "@#zz"},
			{"hostname starting hash equals key-id rendered", "hostname", "#zz", "key-id", "zz"},
		}
		for _, pair := range pairs {
			t.Run(pair.name, func(t *testing.T) {
				requireCollision17772(t, identityPair17772(pair.aType, pair.a, pair.bType, pair.b))
			})
		}
	})

	t.Run("cross-type distinct rendered owners commit", func(t *testing.T) {
		requireNoCollision17772(t, identityPair17772("email", "peer@corp.example", "hostname", "peer@corp.example"))
		requireNoCollision17772(t, identityPair17772("hostname", "zz", "key-id", "zz"))
		requireNoCollision17772(t, identityPair17772("distinguished-name", "CN=peer.example.com", "inet", "peer.example.com"))
	})

	t.Run("remote identity equal to default gateway local address is refused", func(t *testing.T) {
		cmds := identityPair17772("inet", "198.51.100.7", "hostname", "gw-b.example.com", "set security ike gateway gw-b local-address 198.51.100.7")
		requireCollision17772(t, cmds)
	})

	t.Run("remote identity equal to VPN local-address override is refused", func(t *testing.T) {
		cmds := append(identityPair17772("inet", "198.51.100.7", "hostname", "gw-b.example.com"), "set security ipsec vpn vpn-b local-address 198.51.100.7")
		requireCollision17772(t, cmds)
	})

	t.Run("different default local address remains distinct", func(t *testing.T) {
		cmds := identityPair17772("inet", "198.51.100.7", "hostname", "gw-b.example.com", "set security ike gateway gw-b local-address 198.51.100.8")
		requireNoCollision17772(t, cmds)
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
