package config

import (
	"strings"
	"testing"
)

// #16676: an inline-endpoint VPN named like a gateway object referenced
// by another VPN must fail strict commit; tolerant load warns and keeps
// both (render separates them). Controls: same-gateway sharing, an
// unreferenced gateway with a colliding name, and a VPN named after its
// OWN gateway must commit.

func TestIPsecGatewayNameCollision16676(t *testing.T) {
	preamble := []string{
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-p1 authentication-algorithm sha-256",
		"set security ike proposal ike-p1 dh-group group14",
		"set security ike policy ike-pol proposals ike-p1",
		"set security ike policy ike-pol pre-shared-key ascii-text secret-one",
		"set security ike gateway siteA ike-policy ike-pol",
		"set security ike gateway siteA address 10.200.0.3",
		"set security ipsec proposal prop1 protocol esp",
		"set security ipsec proposal prop1 encryption-algorithm aes-256-gcm",
		"set security ipsec proposal prop1 authentication-algorithm hmac-sha-256-128",
		"set security ipsec policy ipsec-pol proposals prop1",
	}
	vpnZZZ := []string{
		"set security ipsec vpn zzz ike gateway siteA",
		"set security ipsec vpn zzz bind-interface st0.0",
		"set security ipsec vpn zzz ike ipsec-policy ipsec-pol",
	}
	vpnInline := []string{
		"set security ipsec vpn siteA ike gateway 10.200.0.1",
		"set security ipsec vpn siteA bind-interface st0.1",
		"set security ipsec vpn siteA ike ipsec-policy ipsec-pol",
		"set security ipsec vpn siteA pre-shared-key ascii-text inline-secret",
	}
	join := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	defect := join(preamble, vpnZZZ, vpnInline)
	// Build trees via the 9624 helper shape: setTree9624 prepends a gw1
	// gateway; instead build directly here.
	build := func(lines []string) *ConfigTree {
		tree := &ConfigTree{}
		for _, cmd := range lines {
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

	cfg, err := CompileConfig(build(defect))
	if err == nil {
		t.Fatalf("DEFECT: strict commit must reject inline VPN siteA colliding with gateway siteA, got cfg %+v", cfg)
	}
	if msg := err.Error(); !strings.Contains(msg, "siteA") || !strings.Contains(msg, "#16676") {
		t.Fatalf("DEFECT error must name siteA and #16676, got: %v", err)
	}

	lenient, lerr := CompileConfigLenient(build(defect))
	if lerr != nil {
		t.Fatalf("tolerant load must not fail: %v", lerr)
	}
	warned := false
	for _, w := range lenient.Warnings {
		if strings.Contains(w, "ipsec gateway name collision") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("tolerant load must warn 'ipsec gateway name collision', warnings=%q", lenient.Warnings)
	}
	if lenient.Security.IPsec.VPNs["zzz"] == nil || lenient.Security.IPsec.VPNs["siteA"] == nil {
		t.Errorf("tolerant load must keep both VPNs, got %v", lenient.Security.IPsec.VPNs)
	}

	// CONTROL 1: two VPNs sharing the SAME gateway object commit.
	controlShared := join(preamble, vpnZZZ, []string{
		"set security ipsec vpn aaa ike gateway siteA",
		"set security ipsec vpn aaa bind-interface st0.1",
		"set security ipsec vpn aaa ike ipsec-policy ipsec-pol",
	})
	if _, err := CompileConfig(build(controlShared)); err != nil {
		t.Errorf("CONTROL shared-gateway must commit, got %v", err)
	}
	// CONTROL 2: gateway named siteA exists but NO vpn references it;
	// inline VPN siteA alone commits (no second peer to fold with).
	controlUnref := join(preamble, vpnInline)
	if _, err := CompileConfig(build(controlUnref)); err != nil {
		t.Errorf("CONTROL unreferenced-gateway must commit, got %v", err)
	}
}
