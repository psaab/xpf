package config

import (
	"strings"
	"testing"
)

// buildTree5630 compiles a set-command list into a ConfigTree for the #5630
// IPsec endpoint-validation tests. It deliberately uses the flat-set
// ParseSetCommand + SetPath path (never NewParser) per CLAUDE.md.
func buildTree5630(t *testing.T, setCommands []string) *ConfigTree {
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

// TestValidateIPsecEndpoints_Reject covers #5630 (codex-review-181 M20 /
// A3-b01-F002): a printable-but-invalid IPsec endpoint — a malformed IP
// octet (10.0.0.999) or a malformed FQDN — used to pass strict commit and
// then be interpolated verbatim into the swanctl remote_addrs / local_addrs
// settings, where strongSwan's `swanctl --load-all` rejects or mishandles
// it (a config that commits but never loads = a silently broken tunnel).
//
// Each case defines a gateway with an OTHERWISE-valid reference so the #2074
// gateway-cross-reference gate passes, isolating the new endpoint gate. Every
// case here compiles cleanly against pre-fix code (the endpoint was never
// validated), so reverting validateIPsecEndpointsStrict (or the all-numeric-
// TLD hardening in isPlausibleHostname) makes these go RED.
func TestValidateIPsecEndpoints_Reject(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub string // substring the error must name
	}{
		{
			name: "malformed remote gateway address (botched IP)",
			cmds: []string{
				"set security ike gateway gw address 10.0.0.999",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
			wantSub: "10.0.0.999",
		},
		{
			name: "malformed remote gateway address (five octets)",
			cmds: []string{
				"set security ike gateway gw address 1.2.3.4.5",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
			wantSub: "1.2.3.4.5",
		},
		{
			name: "malformed remote gateway address (bad FQDN)",
			cmds: []string{
				"set security ike gateway gw address bad..host",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
			wantSub: "bad..host",
		},
		{
			name: "malformed dynamic hostname",
			cmds: []string{
				"set security ike gateway gw dynamic hostname -bad.example.com",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
			wantSub: "-bad.example.com",
		},
		{
			name: "malformed gateway local-address",
			cmds: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 10.0.0.999",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
			wantSub: "local-address",
		},
		{
			name: "malformed vpn local-address",
			cmds: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun local-address 10.0.0.999",
			},
			wantSub: "local-address",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := buildTree5630(t, c.cmds)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile should REJECT a printable-invalid endpoint")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("error should name %q, got: %v", c.wantSub, err)
			}
		})
	}
}

// TestValidateIPsecEndpoints_Accept pins that every VALID endpoint form — a
// literal IPv4, a literal IPv6, and a valid dotted FQDN, for both the remote
// gateway address and the local addresses — still commits cleanly. This is
// the over-rejection guard: the fix must not turn away a legitimate hostname
// or v6 gateway.
func TestValidateIPsecEndpoints_Accept(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "valid IPv4 remote address",
			cmds: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "valid IPv6 remote address",
			cmds: []string{
				"set security ike gateway gw address 2001:db8::1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "valid FQDN remote address",
			cmds: []string{
				"set security ike gateway gw address peer.example.com",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "valid FQDN dynamic hostname",
			cmds: []string{
				"set security ike gateway gw dynamic hostname vpn.example.com",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "valid IPv4 local-addresses (gateway + vpn)",
			cmds: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 198.51.100.7",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun local-address 198.51.100.8",
			},
		},
		{
			name: "valid IPv6 local-address",
			cmds: []string{
				"set security ike gateway gw address 2001:db8::1",
				"set security ike gateway gw local-address 2001:db8::2",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "valid absolute FQDN (trailing dot)",
			cmds: []string{
				"set security ike gateway gw address peer.example.com.",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := buildTree5630(t, c.cmds)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("valid endpoint should COMMIT, got: %v", err)
			}
		})
	}
}

// TestValidateIPsecEndpoints_Lenient covers the #1960 fail-closed-on-load
// doctrine: a config carrying a printable-invalid endpoint that an older
// binary persisted (or a peer synced) must still BOOT under the tolerant
// compile paths — the strict path rejects, the lenient path warns and loads.
func TestValidateIPsecEndpoints_Lenient(t *testing.T) {
	cmds := []string{
		"set security ike gateway gw address 10.0.0.999",
		"set security ipsec vpn tun gateway gw",
	}
	tree := buildTree5630(t, cmds)

	// Strict rejects.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile should reject the malformed endpoint")
	}

	// Lenient boots with a warning (both entry points).
	for _, tc := range []struct {
		name    string
		compile func() (*Config, error)
	}{
		{"lenient", func() (*Config, error) { return CompileConfigLenient(tree) }},
		{"lenient-for-node", func() (*Config, error) { return CompileConfigForNodeLenient(tree, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile()
			if err != nil {
				t.Fatalf("lenient compile should BOOT a malformed-endpoint config, got: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ipsec endpoint") && strings.Contains(w, "10.0.0.999") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile should record an ipsec endpoint warning, got: %v", cfg.Warnings)
			}
		})
	}
}
