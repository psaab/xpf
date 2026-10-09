package config

import (
	"strings"
	"testing"
)

// ikeVRF12089Base is the minimal strict-clean IKE gateway spelling. Every
// #12089 fixture builds on it so the ONLY commit error/warning a fixture can
// draw is this gate's.
func ikeVRF12089Base(gw, addr, ext string) []string {
	return []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set security ike gateway " + gw + " address " + addr,
		"set security ike gateway " + gw + " external-interface " + ext,
	}
}

func ikeVRF12089Warnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#12089") {
			out = append(out, w)
		}
	}
	return out
}

// TestIKEGatewayRoutingInstanceRefused12089: an IKE gateway whose effective
// local address resolves to a non-default routing-instance must be refused
// at strict commit, naming the gateway and the instance. Neither strongSwan
// nor the xfrmi is scoped to that instance, so outer IKE/ESP would be routed
// in the wrong table.
func TestIKEGatewayRoutingInstanceRefused12089(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		gw    string
		ri    string
	}{
		{
			name: "unit-ref member",
			lines: append(ikeVRF12089Base("gw", "203.0.113.1", "ge-0/0/1.0"),
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.0",
			),
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "ipsec gateway stanza",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set security ipsec gateway gw address 203.0.113.1",
				"set security ipsec gateway gw external-interface ge-0/0/1.0",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.0",
			},
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "bare member fans down to unit",
			lines: append(ikeVRF12089Base("gw", "203.0.113.1", "ge-0/0/1.0"),
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1",
			),
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "bare external-interface selects nonzero addressed unit",
			lines: []string{
				"set interfaces ge-0/0/1 unit 1 family inet address 192.0.2.1/24",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.1",
			},
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "bare external-interface selects first matching family unit",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::1/64",
				"set interfaces ge-0/0/1 unit 1 family inet address 192.0.2.1/24",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.1",
			},
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "P1 gateway local-address selects VR unit without external-interface",
			lines: []string{
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 198.51.100.1",
			},
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "P2 gateway local-address overrides default external-interface",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ike gateway gw local-address 198.51.100.1",
			},
			gw: "gw",
			ri: "VR1",
		},
		{
			name: "P21 VPN local-address overrides default gateway source",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun local-address 198.51.100.1",
			},
			gw: "gw",
			ri: "VR1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, tc.lines))
			if err == nil {
				t.Fatalf("strict commit accepted IKE gateway %q with an instance-owned effective local address; want reject naming gateway + instance %q", tc.gw, tc.ri)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.gw) || !strings.Contains(msg, tc.ri) {
				t.Fatalf("reject %q names neither gateway %q nor instance %q; want both", msg, tc.gw, tc.ri)
			}
			if !strings.Contains(msg, "#12089") {
				t.Fatalf("reject %q does not carry #12089 identity", msg)
			}
		})
	}
}

// TestIKEGatewayRoutingInstanceAccepted12089: control rows — a gateway whose
// effective local address is in the default instance, a gateway with no
// external-interface, and a gateway whose external-interface names an
// undeclared interface must not be rejected by this gate.
func TestIKEGatewayRoutingInstanceAccepted12089(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name:  "default instance interface",
			lines: ikeVRF12089Base("gw", "203.0.113.1", "ge-0/0/1.0"),
		},
		{
			name: "bare external-interface ignores later scoped unit",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/1 unit 1 family inet address 198.51.100.1/24",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.1",
			},
		},
		{
			name: "unit-specific external-interface ignores sibling unit",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/1 unit 1 family inet address 198.51.100.1/24",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.1",
			},
		},
		{
			name: "P15 gateway local-address overrides VR external-interface",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/2.0",
				"set security ike gateway gw local-address 192.0.2.1",
			},
		},
		{
			name: "P22 VPN local-address overrides VR gateway source",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/2.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun local-address 192.0.2.1",
			},
		},
		{
			name: "no external-interface",
			lines: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
			},
		},
		{
			name: "undeclared external-interface left to other gates",
			lines: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/9.0",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("strict commit rejected in-scope-clean gateway: %v", err)
			}
			if warns := ikeVRF12089Warnings(cfg); len(warns) != 0 {
				t.Fatalf("unexpected #12089 warnings: %v", warns)
			}
		})
	}
}

// TestIKEGatewayRoutingInstanceLenient12089: #1960 fail-closed-on-load — a
// persisted or peer-synced config carrying the unsupported scope must still
// boot under the tolerant compile paths, with a warning naming gateway and
// instance.
func TestIKEGatewayRoutingInstanceLenient12089(t *testing.T) {
	lines := append(ikeVRF12089Base("gw", "203.0.113.1", "ge-0/0/1.0"),
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface ge-0/0/1.0",
	)
	tree := buildTree4953(t, lines)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile should reject the instance-owned IKE gateway")
	}
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
				t.Fatalf("lenient compile should BOOT an instance-owned-gateway config, got: %v", err)
			}
			warns := ikeVRF12089Warnings(cfg)
			if len(warns) != 1 {
				t.Fatalf("lenient compile should record exactly one #12089 warning, got: %v", cfg.Warnings)
			}
			if !strings.Contains(warns[0], "gw") || !strings.Contains(warns[0], "VR1") {
				t.Fatalf("warning %q names neither gateway nor instance; want both", warns[0])
			}
		})
	}
}

func TestIKEGatewayRoutingInstanceEffectiveLocalAddressLenient12089(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{
			name: "P1 gateway local-address without external-interface",
			lines: []string{
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 198.51.100.1",
			},
		},
		{
			name: "P2 gateway local-address overrides default external-interface",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ike gateway gw local-address 198.51.100.1",
			},
		},
		{
			name: "P21 VPN local-address overrides default gateway source",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun local-address 198.51.100.1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant compile rejected unsupported local-address scope: %v", err)
			}
			warns := ikeVRF12089Warnings(cfg)
			if len(warns) != 1 || !strings.Contains(warns[0], "VR1") {
				t.Fatalf("tolerant compile warnings = %v, want one #12089 warning naming VR1", warns)
			}
		})
	}
}

func TestIKEGatewayRoutingInstanceMembershipPriority12089(t *testing.T) {
	cases := []struct {
		name      string
		lines     []string
		wantIssue string
	}{
		{
			name: "forwarding member remains owned by #11312",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set routing-instances FWD instance-type forwarding",
				"set routing-instances FWD interface ge-0/0/1.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
			},
			wantIssue: "#11312",
		},
		{
			name: "dual claim remains owned by #11060",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/1.0",
				"set routing-instances VR2 instance-type virtual-router",
				"set routing-instances VR2 interface ge-0/0/1.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
			},
			wantIssue: "#11060",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, tc.lines))
			if err == nil || !strings.Contains(err.Error(), tc.wantIssue) {
				t.Fatalf("strict error = %v, want %s to retain diagnostic priority", err, tc.wantIssue)
			}
			if strings.Contains(err.Error(), "#12089") {
				t.Fatalf("strict error %q was pre-empted by #12089", err)
			}

			cfg, err := CompileConfigLenient(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant compile rejected membership diagnostic: %v", err)
			}
			foundIssue := false
			for _, warning := range cfg.Warnings {
				foundIssue = foundIssue || strings.Contains(warning, tc.wantIssue)
			}
			if !foundIssue {
				t.Fatalf("tolerant warnings %v do not retain %s diagnostic", cfg.Warnings, tc.wantIssue)
			}
			if warns := ikeVRF12089Warnings(cfg); len(warns) != 0 {
				t.Fatalf("membership issue also produced false #12089 warnings: %v", warns)
			}
		})
	}
}

func TestIKEGatewayRoutingInstanceChecksEachVPNSource12089(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface ge-0/0/2.0",
		"set security ike gateway gw address 203.0.113.1",
		"set security ike gateway gw external-interface ge-0/0/1.0",
		"set security ipsec vpn a-default gateway gw",
		"set security ipsec vpn a-default bind-interface st0",
		"set security ipsec vpn a-default local-address 192.0.2.1",
		"set security ipsec vpn z-vr gateway gw",
		"set security ipsec vpn z-vr bind-interface st0.1",
		"set security ipsec vpn z-vr local-address 198.51.100.1",
	}
	_, err := CompileConfig(buildTree4953(t, lines))
	if err == nil || !strings.Contains(err.Error(), `vpn "z-vr"`) ||
		strings.Contains(err.Error(), `vpn "a-default"`) || !strings.Contains(err.Error(), "VR1") {
		t.Fatalf("strict error = %v, want only the VR-sourced VPN z-vr and VR1", err)
	}

	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile rejected mixed VPN sources: %v", err)
	}
	warns := ikeVRF12089Warnings(cfg)
	if len(warns) != 1 || !strings.Contains(warns[0], `vpn "z-vr"`) ||
		strings.Contains(warns[0], `vpn "a-default"`) {
		t.Fatalf("tolerant #12089 warnings = %v, want only z-vr", warns)
	}
}

func TestIKEGatewayRoutingInstanceInlineVPNLocalAddress12089(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface ge-0/0/2.0",
		"set security ipsec vpn tun gateway 203.0.113.1",
		"set security ipsec vpn tun bind-interface st0",
		"set security ipsec vpn tun local-address 198.51.100.1",
	}
	_, err := CompileConfig(buildTree4953(t, lines))
	if err == nil || !strings.Contains(err.Error(), `ipsec vpn "tun"`) ||
		!strings.Contains(err.Error(), "VR1") || !strings.Contains(err.Error(), "#12089") {
		t.Fatalf("strict error = %v, want inline VPN local-address rejection naming tun and VR1", err)
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("tolerant compile rejected inline VPN local-address: %v", err)
	}
	warns := ikeVRF12089Warnings(cfg)
	if len(warns) != 1 || !strings.Contains(warns[0], `ipsec vpn "tun"`) {
		t.Fatalf("tolerant #12089 warnings = %v, want one inline VPN warning", warns)
	}
}
