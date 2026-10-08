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

// TestIKEGatewayRoutingInstanceRefused12089: an IKE gateway whose
// external-interface lives in a non-default routing-instance must be refused
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, tc.lines))
			if err == nil {
				t.Fatalf("strict commit accepted IKE gateway %q on instance-owned external-interface; want reject naming gateway + instance %q", tc.gw, tc.ri)
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

// TestIKEGatewayRoutingInstanceAccepted12089: control rows — a gateway on a
// default-instance interface, a gateway with no external-interface, and a
// gateway whose external-interface names an undeclared interface must still
// commit cleanly. This gate owns only the instance-owned scope.
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
