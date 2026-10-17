package config

import (
	"strings"
	"testing"
)

// #14393: the #12089 gate must fail closed when a VPN's EFFECTIVE source
// cannot be mapped to any declared interface address while a non-default
// routing-instance with members exists. Today every unmappable source
// (no source pinning, a hostname local-address, or an IP literal not
// declared in the config) returns empty instances and is treated as
// clean, so charon renders a connection with no source pinning (no
// local_addrs at all, or a verbatim hostname/undeclared literal) and can
// bind VR-owned addresses.

func unmappable14393Base() []string {
	return []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface ge-0/0/2.0",
	}
}

func TestIKEGatewayRoutingInstanceUnmappableSource14393(t *testing.T) {
	cases := []struct {
		name   string
		lines  []string
		vpn    string
		source string
	}{
		{
			name: "no source pinning gateway with VPN",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			),
			vpn:    "tun",
			source: "external-interface",
		},
		{
			name: "hostname gateway local-address",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address vpn-gw.example.com",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			),
			vpn:    "tun",
			source: "vpn-gw.example.com",
		},
		{
			name: "undeclared literal gateway local-address",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 198.51.100.99",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			),
			vpn:    "tun",
			source: "198.51.100.99",
		},
		{
			name: "hostname VPN local-address overrides mappable gateway",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
				"set security ipsec vpn tun local-address vpn-gw.example.com",
			),
			vpn:    "tun",
			source: "vpn-gw.example.com",
		},
		{
			name: "undeclared literal VPN local-address",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/1.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
				"set security ipsec vpn tun local-address 198.51.100.99",
			),
			vpn:    "tun",
			source: "198.51.100.99",
		},
		{
			name: "gateway-less VPN hostname local-address",
			lines: append(unmappable14393Base(),
				"set security ipsec vpn tun gateway 203.0.113.1",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
				"set security ipsec vpn tun local-address vpn-gw.example.com",
			),
			vpn:    "tun",
			source: "vpn-gw.example.com",
		},
		{
			name: "gateway-less VPN undeclared literal local-address",
			lines: append(unmappable14393Base(),
				"set security ipsec vpn tun gateway 203.0.113.1",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
				"set security ipsec vpn tun local-address 198.51.100.99",
			),
			vpn:    "tun",
			source: "198.51.100.99",
		},
		{
			name: "gateway-less VPN with no local-address and VR present",
			lines: append(unmappable14393Base(),
				"set security ipsec vpn tun gateway 203.0.113.1",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			),
			vpn:    "tun",
			source: "no local-address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			_, err := CompileConfig(buildTree4953(t, tc.lines))
			if err == nil {
				t.Fatalf("strict commit accepted VPN %q with unmappable effective source %q while VR1 has members; want #12089 reject", tc.vpn, tc.source)
			}
			msg := err.Error()
			if !strings.Contains(msg, "#12089") || !strings.Contains(msg, tc.vpn) || !strings.Contains(msg, tc.source) {
				t.Fatalf("reject %q must name #12089, vpn %q and source %q", msg, tc.vpn, tc.source)
			}
		})
		t.Run(tc.name+"/lenient", func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient compile should boot, got: %v", err)
			}
			warns := ikeVRF12089Warnings(cfg)
			matched := false
			for _, w := range warns {
				if strings.Contains(w, tc.vpn) && strings.Contains(w, tc.source) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("lenient warnings %v must name vpn %q and source %q (#12089)", warns, tc.vpn, tc.source)
			}
			if _, ok := cfg.Security.IPsec.VPNs[tc.vpn]; ok {
				t.Fatalf("lenient compile kept unmappable VPN %q; want it removed so the renderer emits no unpinned connection", tc.vpn)
			}
		})
	}
}

func TestIKEGatewayRoutingInstanceUnmappableControls14393(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		keepVPN string
	}{
		{
			name: "mappable gateway local-address still accepted",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address 192.0.2.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			),
			keepVPN: "tun",
		},
		{
			name: "mappable VPN local-address still accepted",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/2.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
				"set security ipsec vpn tun local-address 192.0.2.1",
			),
			keepVPN: "tun",
		},
		{
			name: "no-source VPN with no VR stays accepted",
			lines: []string{
				"set security ike gateway gw address 203.0.113.1",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			},
			keepVPN: "tun",
		},
		{
			name: "hostname local-address with no VR stays accepted",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw local-address vpn-gw.example.com",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			},
			keepVPN: "tun",
		},
		{
			name: "bare gateway undeclared external-interface no VPN",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/9.0",
			),
		},
		{
			name: "bare gateway no source no VPN with VR present",
			lines: append(unmappable14393Base(),
				"set security ike gateway gw address 203.0.113.1",
			),
		},
		{
			name: "external-interface on declared unit with no address is mappable",
			lines: []string{
				"set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
				"set interfaces ge-0/0/2 unit 0 family inet address 198.51.100.1/24",
				"set interfaces ge-0/0/3 unit 0",
				"set routing-instances VR1 instance-type virtual-router",
				"set routing-instances VR1 interface ge-0/0/2.0",
				"set security ike gateway gw address 203.0.113.1",
				"set security ike gateway gw external-interface ge-0/0/3.0",
				"set security ipsec vpn tun gateway gw",
				"set security ipsec vpn tun bind-interface st0",
				"set security ipsec vpn tun pre-shared-key fixture-secret",
			},
			keepVPN: "tun",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			cfg, err := CompileConfig(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("strict commit rejected control: %v", err)
			}
			if warns := ikeVRF12089Warnings(cfg); len(warns) != 0 {
				t.Fatalf("control drew #12089 warnings: %v", warns)
			}
			if tc.keepVPN != "" {
				if _, ok := cfg.Security.IPsec.VPNs[tc.keepVPN]; !ok {
					t.Fatalf("strict control lost VPN %q", tc.keepVPN)
				}
			}
		})
		t.Run(tc.name+"/lenient", func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree4953(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient compile rejected control: %v", err)
			}
			if warns := ikeVRF12089Warnings(cfg); len(warns) != 0 {
				t.Fatalf("control drew #12089 warnings: %v", warns)
			}
			if tc.keepVPN != "" {
				if _, ok := cfg.Security.IPsec.VPNs[tc.keepVPN]; !ok {
					t.Fatalf("lenient control lost VPN %q", tc.keepVPN)
				}
			}
		})
	}
}

func TestIKEGatewayRoutingInstanceUnmappableMixedVPNs14393(t *testing.T) {
	lines := append(unmappable14393Base(),
		"set security ike gateway gw address 203.0.113.1",
		"set security ike gateway gw external-interface ge-0/0/1.0",
		"set security ipsec vpn good gateway gw",
		"set security ipsec vpn good bind-interface st0",
		"set security ipsec vpn good pre-shared-key fixture-secret",
		"set security ipsec vpn good local-address 192.0.2.1",
		"set security ipsec vpn bad gateway gw",
		"set security ipsec vpn bad bind-interface st0.1",
		"set security ipsec vpn bad pre-shared-key fixture-secret",
		"set security ipsec vpn bad local-address vpn-gw.example.com",
	)
	_, err := CompileConfig(buildTree4953(t, lines))
	if err == nil || !strings.Contains(err.Error(), `"bad"`) || strings.Contains(err.Error(), `"good"`) {
		t.Fatalf("strict error = %v, want only VPN bad named", err)
	}
	cfg, err := CompileConfigLenient(buildTree4953(t, lines))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if _, ok := cfg.Security.IPsec.VPNs["good"]; !ok {
		t.Fatalf("lenient compile lost mappable VPN good")
	}
	if _, ok := cfg.Security.IPsec.VPNs["bad"]; ok {
		t.Fatalf("lenient compile kept unmappable VPN bad")
	}
	warns := ikeVRF12089Warnings(cfg)
	if len(warns) != 1 || !strings.Contains(warns[0], `"bad"`) {
		t.Fatalf("lenient warnings = %v, want exactly one naming bad", warns)
	}
}
