package config

import (
	"strings"
	"testing"
)

// buildTree2074 compiles a set-command list into a ConfigTree for the
// #2074 gateway-reference tests.
func buildTree2074(t *testing.T, setCommands []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestValidateIPsecGatewayReferences covers #2074: a VPN that references
// an IKE gateway which is neither defined+addressed nor a usable inline
// IP/hostname must be rejected at commit (strict), while valid shapes
// compile cleanly. These cases fail against pre-fix code, which compiled
// such configs without error (and then rendered a dead remote_addrs).
func TestValidateIPsecGatewayReferences(t *testing.T) {
	t.Run("commit rejects undefined gateway", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			"set security ipsec vpn tun gateway nope",
			"set security ipsec vpn tun bind-interface st0.0",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject a VPN referencing undefined gateway %q", "nope")
		}
		if !strings.Contains(err.Error(), "nope") {
			t.Fatalf("error should name the offending gateway, got: %v", err)
		}
	})

	t.Run("commit rejects addressless gateway", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			// Gateway object exists (it has an ike-policy) but no address
			// and no dynamic hostname.
			"set security ike gateway bare-gw ike-policy pol1",
			"set security ipsec vpn tun gateway bare-gw",
			"set security ipsec vpn tun bind-interface st0.0",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject an addressless gateway reference")
		}
		if !strings.Contains(err.Error(), "bare-gw") {
			t.Fatalf("error should name the offending gateway, got: %v", err)
		}
	})

	t.Run("commit accepts inline literal IP gateway", func(t *testing.T) {
		// Mirrors parser_security_test.go `vpn site-a gateway 10.1.0.1`.
		tree := buildTree2074(t, []string{
			"set security ipsec vpn site-a gateway 10.1.0.1",
			"set security ipsec vpn site-a bind-interface st0.0",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("inline IP gateway should compile, got: %v", err)
		}
	})

	t.Run("commit accepts defined gateway with address", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			"set security ike gateway remote-gw address 203.0.113.1",
			"set security ipsec vpn tun gateway remote-gw",
			"set security ipsec vpn tun bind-interface st0.0",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("defined+addressed gateway should compile, got: %v", err)
		}
	})

	t.Run("commit accepts dynamic-hostname gateway", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			"set security ike gateway dyn-gw dynamic hostname peer.example.com",
			"set security ipsec vpn tun gateway dyn-gw",
			"set security ipsec vpn tun bind-interface st0.0",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("dynamic-hostname gateway should compile, got: %v", err)
		}
	})

	// Stanza-order independence (round-2 R2-2): the VPN's gateway is
	// defined under `ike { gateway ... }`. The validator must run on the
	// fully-compiled config, not order-dependently — so the VPN compiles
	// regardless of whether `ipsec` set-commands appear before `ike` ones.
	t.Run("ipsec stanza before ike stanza still compiles", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			// VPN (ipsec subtree) authored first ...
			"set security ipsec vpn tun gateway hub-gw",
			"set security ipsec vpn tun bind-interface st0.0",
			// ... ike gateway authored after.
			"set security ike gateway hub-gw address 198.51.100.1",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("ike-defined gateway authored after the VPN should still compile, got: %v", err)
		}
	})

	// Lenient load/peer-sync (round-2 R2-2 / #1960): a config carrying a
	// dangling-gateway VPN must still BOOT under the tolerant compile
	// paths (warn, do not fail) so an upgraded / peer-synced node loads.
	t.Run("lenient load warns but does not fail", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			"set security ipsec vpn tun gateway nope",
		})
		// Strict rejects.
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("strict compile should reject the dangling gateway")
		}
		// Lenient boots with a warning.
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should boot a dangling-gateway config, got: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "ipsec gateway reference") && strings.Contains(w, "nope") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile should record an ipsec gateway warning, got: %v", cfg.Warnings)
		}
	})

	t.Run("lenient for-node load warns but does not fail", func(t *testing.T) {
		tree := buildTree2074(t, []string{
			"set security ipsec vpn tun gateway nope",
		})
		cfg, err := CompileConfigForNodeLenient(tree, 0)
		if err != nil {
			t.Fatalf("lenient for-node compile should boot a dangling-gateway config, got: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "ipsec gateway reference") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient for-node compile should record an ipsec gateway warning, got: %v", cfg.Warnings)
		}
	})

	t.Run("no gateway is not rejected", func(t *testing.T) {
		// A VPN may legitimately omit the gateway (cert/TS-only shapes).
		tree := buildTree2074(t, []string{
			"set security ipsec vpn tun bind-interface st0.0",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("a gateway-less VPN should compile, got: %v", err)
		}
	})
}

// TestIsUsableIPsecEndpoint exercises the shared predicate directly.
func TestIsUsableIPsecEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"10.0.0.1", true},
		{"2001:db8::1", true},
		{"peer.example.com", true},
		{"a.b", true},
		{"vpnpeer", false}, // dotless single-label name (Rule A)
		{"typo-gw", false}, // dotless object-name typo
		{"gw_underscore", false},
		{"-bad.example.com", false}, // leading hyphen label
		{"bad-.example.com", false}, // trailing hyphen label
		{".example.com", false},     // empty leading label
		{"a..b", false},             // empty middle label
		{"has space.com", false},
		// Absolute FQDN with a single trailing dot is valid (Junos
		// accepts it; the terminal dot is the absolute-root marker, not
		// an empty last label).
		{"vpn.example.com.", true},
		{"example.com.", true},
		// ...but the single trailing dot must be the ONLY relaxation:
		{"example.com..", false},    // double trailing dot => empty last label
		{".", false},                // only a dot
		{"vpn..example.com", false}, // interior empty label
		{"vpn.bad-.", false},        // trailing dot, last real label ends with hyphen
	}
	for _, c := range cases {
		if got := IsUsableIPsecEndpoint(c.in); got != c.want {
			t.Errorf("IsUsableIPsecEndpoint(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestIsUsableIPsecEndpointMaxLength pins the 253-octet presentation-form
// length boundary and its interaction with the absolute-root trailing dot
// (#2596). RFC 1035 §3.1 caps the presentation name at 253 characters
// (excluding the trailing root dot); a maximal 253-char FQDN written in
// absolute form is 254 bytes including the "." and must be accepted. The
// pre-#2596 code applied the byte-length cap BEFORE stripping the trailing
// dot, so the 254-byte absolute form was wrongly rejected. This test goes
// RED if the strip-then-cap ordering is reverted.
func TestIsUsableIPsecEndpointMaxLength(t *testing.T) {
	// makeName builds a dotted multi-label hostname of exactly n characters
	// (n >= 1). Labels are kept at <=63 chars so each label is individually
	// valid; the total length is what we are pinning here.
	makeName := func(n int) string {
		var b strings.Builder
		for b.Len() < n {
			if b.Len() > 0 {
				b.WriteByte('.')
				if b.Len() == n {
					break
				}
			}
			// Fill this label up to 63 chars or until we hit n.
			label := 0
			for b.Len() < n && label < 63 {
				b.WriteByte('a')
				label++
			}
		}
		return b.String()
	}

	name253 := makeName(253)
	if len(name253) != 253 {
		t.Fatalf("makeName(253) produced len %d, want 253", len(name253))
	}
	name254 := makeName(254)
	if len(name254) != 254 {
		t.Fatalf("makeName(254) produced len %d, want 254", len(name254))
	}

	cases := []struct {
		name string
		in   string
		want bool
	}{
		// 253-char relative FQDN: at the cap, valid.
		{"253-char", name253, true},
		// 253-char name with a trailing root dot: 254 bytes on the wire,
		// but only 253 presentation chars => valid (#2596). This is the
		// case the pre-fix ordering wrongly rejected.
		{"253-char+trailing-dot", name253 + ".", true},
		// 254-char relative FQDN: one over the cap, invalid.
		{"254-char", name254, false},
		// 254-char name with a trailing dot: after stripping the dot the
		// stripped name is still 254 chars => over the cap, invalid.
		{"254-char+trailing-dot", name254 + ".", false},
		// Edge cases around the strip itself.
		{"empty", "", false},
		{"bare-dot", ".", false},
	}
	for _, c := range cases {
		if got := IsUsableIPsecEndpoint(c.in); got != c.want {
			t.Errorf("%s: IsUsableIPsecEndpoint(len=%d) = %v, want %v",
				c.name, len(c.in), got, c.want)
		}
	}
}
