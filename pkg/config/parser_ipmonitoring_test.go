package config

import (
	"strings"
	"testing"
)

// rpmProbeLines returns the set lines for a probe the ip-monitoring
// policies under test can reference.
func rpmProbeLines() []string {
	return []string{
		"set services rpm probe WAN test wan-a probe-type icmp-ping",
		"set services rpm probe WAN test wan-a target address 1.1.1.1",
		"set services rpm probe WAN test wan-a destination-interface reth0.50",
		"set services rpm probe WAN test wan-a next-hop 172.16.50.1",
		"set services rpm probe WAN test wan-a thresholds successive-loss 3",
	}
}

// TestIPMonitoringFlatSet covers the plan §4.1 example config in flat
// set syntax (ParseSetCommand + SetPath).
func TestIPMonitoringFlatSet(t *testing.T) {
	lines := append(rpmProbeLines(),
		"set routing-instances ISP-B instance-type virtual-router",
		"set services ip-monitoring policy wan-failover match rpm-probe WAN",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop 172.16.80.1",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 preferred-metric 10",
		"set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1",
		"set services ip-monitoring policy wan-failover hold-down 5",
	)
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil {
		t.Fatal("policy wan-failover not compiled")
	}
	if pol.MatchRPMProbe != "WAN" {
		t.Fatalf("MatchRPMProbe = %q, want WAN", pol.MatchRPMProbe)
	}
	if pol.HoldDownSecs != 5 {
		t.Fatalf("HoldDownSecs = %d, want 5", pol.HoldDownSecs)
	}
	if len(pol.PreferredRoutes) != 2 {
		t.Fatalf("PreferredRoutes = %+v, want 2 (master merged + ISP-B)", pol.PreferredRoutes)
	}
	master := pol.PreferredRoutes[0]
	if master.RoutingInstance != "" || master.Destination != "0.0.0.0/0" ||
		master.NextHop != "172.16.80.1" || master.PreferredMetric != 10 {
		t.Fatalf("master route = %+v (next-hop and preferred-metric lines must merge)", master)
	}
	ri := pol.PreferredRoutes[1]
	if ri.RoutingInstance != "ISP-B" || ri.NextHop != "172.16.80.1" {
		t.Fatalf("routing-instance route = %+v", ri)
	}
}

// TestIPMonitoringHierarchical covers the same stanza in hierarchical
// block syntax.
func TestIPMonitoringHierarchical(t *testing.T) {
	input := `services {
    rpm {
        probe WAN {
            test wan-a {
                target address 1.1.1.1;
                destination-interface reth0.50;
                next-hop 172.16.50.1;
            }
        }
    }
    ip-monitoring {
        policy wan-failover {
            match {
                rpm-probe WAN;
            }
            then {
                preferred-route {
                    route 0.0.0.0/0 {
                        next-hop 172.16.80.1;
                        preferred-metric 10;
                    }
                    routing-instance ISP-B {
                        route 0.0.0.0/0 {
                            next-hop 172.16.80.1;
                        }
                    }
                }
            }
            hold-down 5;
        }
    }
}
routing-instances {
    ISP-B {
        instance-type virtual-router;
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil || pol.MatchRPMProbe != "WAN" || pol.HoldDownSecs != 5 {
		t.Fatalf("policy = %+v", pol)
	}
	if len(pol.PreferredRoutes) != 2 {
		t.Fatalf("PreferredRoutes = %+v, want 2", pol.PreferredRoutes)
	}
	if pol.PreferredRoutes[0].PreferredMetric != 10 {
		t.Fatalf("master metric = %d, want 10", pol.PreferredRoutes[0].PreferredMetric)
	}
	if pol.PreferredRoutes[1].RoutingInstance != "ISP-B" {
		t.Fatalf("second route = %+v", pol.PreferredRoutes[1])
	}
}

func TestIPMonitoringValidation(t *testing.T) {
	cases := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name: "unknown probe rejected",
			lines: []string{
				"set services ip-monitoring policy p match rpm-probe NOPE",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
			},
			wantErr: "does not reference a configured services rpm probe",
		},
		{
			name: "missing match rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
			),
			wantErr: "match rpm-probe is required",
		},
		{
			name: "missing preferred-route rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
			),
			wantErr: "at least one then preferred-route route is required",
		},
		{
			name: "family mismatch rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 2001:db8::1",
			),
			wantErr: "address family does not match destination",
		},
		{
			name: "invalid destination rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route not-a-prefix next-hop 10.0.0.1",
			),
			wantErr: "invalid destination prefix",
		},
		{
			name: "unknown routing-instance rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route routing-instance GHOST route 0.0.0.0/0 next-hop 10.0.0.1",
			),
			wantErr: `routing-instance "GHOST" does not exist`,
		},
		{
			name: "negative hold-down rejected",
			lines: append(rpmProbeLines(),
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
				"set services ip-monitoring policy p hold-down -3",
			),
			wantErr: "hold-down: invalid value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// --- #1844: interface-typed (DHCP-tracked) next-hops ---

// dhcpUplinkLines returns interface set lines for the DHCP uplink units
// the interface-typed next-hop tests reference: unit 0 untagged, unit
// 50 tagged vlan-id 50, unit 1 tagged vlan-id 80 (the unit-number ≠
// vlan-id bridging case), and unit 2 static (no dhcp).
func dhcpUplinkLines() []string {
	return []string{
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 0 family inet dhcp",
		"set interfaces ge-0/0/3 unit 50 vlan-id 50",
		"set interfaces ge-0/0/3 unit 50 family inet dhcp",
		"set interfaces ge-0/0/3 unit 1 vlan-id 80",
		"set interfaces ge-0/0/3 unit 1 family inet dhcp",
		"set interfaces ge-0/0/3 unit 2 vlan-id 2",
		"set interfaces ge-0/0/3 unit 2 family inet address 192.0.2.1/24",
	}
}

// TestIPMonitoringInterfaceNextHopFlatSet: the §4.1 example — an
// interface-typed next-hop compiles to NextHopInterface (the Linux
// DHCP lease key) with NextHop cleared, in flat set syntax.
func TestIPMonitoringInterfaceNextHopFlatSet(t *testing.T) {
	lines := append(rpmProbeLines(), dhcpUplinkLines()...)
	lines = append(lines,
		"set services ip-monitoring policy wan-failover match rpm-probe WAN",
		"set services ip-monitoring policy wan-failover then preferred-route route 0.0.0.0/0 next-hop ge-0/0/3.0",
	)
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil || len(pol.PreferredRoutes) != 1 {
		t.Fatalf("policy = %+v", pol)
	}
	pr := pol.PreferredRoutes[0]
	if pr.NextHopInterface != "ge-0-0-3" {
		t.Fatalf("NextHopInterface = %q, want ge-0-0-3", pr.NextHopInterface)
	}
	if pr.NextHop != "" {
		t.Fatalf("NextHop = %q, want empty (mutually exclusive with NextHopInterface)", pr.NextHop)
	}
}

// TestIPMonitoringInterfaceNextHopHierarchical covers the same form in
// hierarchical block syntax (dual-AST gotcha, #1796/#1797 class).
func TestIPMonitoringInterfaceNextHopHierarchical(t *testing.T) {
	input := `interfaces {
    ge-0/0/3 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}
services {
    rpm {
        probe WAN {
            test wan-a {
                target address 1.1.1.1;
            }
        }
    }
    ip-monitoring {
        policy wan-failover {
            match {
                rpm-probe WAN;
            }
            then {
                preferred-route {
                    route 0.0.0.0/0 {
                        next-hop ge-0/0/3.0;
                    }
                }
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	pr := cfg.Services.IPMonitoring.Policies["wan-failover"].PreferredRoutes[0]
	if pr.NextHopInterface != "ge-0-0-3" || pr.NextHop != "" {
		t.Fatalf("route = %+v, want NextHopInterface=ge-0-0-3 NextHop=\"\"", pr)
	}
}

// TestIPMonitoringInterfaceNextHopLeaseKeyDerivation pins the
// unit-number → vlan-id lease-key bridging (§4.1 check 5): the
// operator writes the UNIT number; the lease key suffix is the unit's
// VLAN ID (the DHCP client binds to the VLAN subinterface).
func TestIPMonitoringInterfaceNextHopLeaseKeyDerivation(t *testing.T) {
	cases := []struct {
		nextHop string
		wantKey string
	}{
		{"ge-0/0/3.0", "ge-0-0-3"},     // untagged unit: no suffix
		{"ge-0/0/3.50", "ge-0-0-3.50"}, // unit 50 vlan-id 50 (coinciding)
		{"ge-0/0/3.1", "ge-0-0-3.80"},  // unit 1 vlan-id 80 (bridged)
	}
	for _, tc := range cases {
		t.Run(tc.nextHop, func(t *testing.T) {
			lines := append(rpmProbeLines(), dhcpUplinkLines()...)
			lines = append(lines,
				"set services ip-monitoring policy p match rpm-probe WAN",
				"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop "+tc.nextHop,
			)
			cfg, err := CompileConfig(buildTree(t, lines))
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}
			pr := cfg.Services.IPMonitoring.Policies["p"].PreferredRoutes[0]
			if pr.NextHopInterface != tc.wantKey {
				t.Fatalf("NextHopInterface = %q, want %q", pr.NextHopInterface, tc.wantKey)
			}
		})
	}
}

// TestIPMonitoringInterfaceNextHopValidation covers the §4.1 commit
// rejections for the interface-typed form.
func TestIPMonitoringInterfaceNextHopValidation(t *testing.T) {
	policy := func(route, nextHop string) []string {
		lines := append(rpmProbeLines(), dhcpUplinkLines()...)
		return append(lines,
			"set services ip-monitoring policy p match rpm-probe WAN",
			"set services ip-monitoring policy p then preferred-route route "+route+" next-hop "+nextHop,
		)
	}
	cases := []struct {
		name    string
		lines   []string
		wantErr string
	}{
		{
			name:    "bare ifd rejected",
			lines:   policy("0.0.0.0/0", "ge-0/0/3"),
			wantErr: "interface-typed next-hop requires <ifd>.<unit>",
		},
		{
			name:    "unknown interface rejected",
			lines:   policy("0.0.0.0/0", "ge-9/9/9.0"),
			wantErr: "is not a valid IP address or DHCP interface unit",
		},
		{
			name:    "dashed linux form rejected",
			lines:   policy("0.0.0.0/0", "ge-0-0-3.0"),
			wantErr: "is not a valid IP address or DHCP interface unit",
		},
		{
			name:    "unknown unit rejected",
			lines:   policy("0.0.0.0/0", "ge-0/0/3.7"),
			wantErr: "has no unit 7",
		},
		{
			name:    "non-DHCP unit rejected",
			lines:   policy("0.0.0.0/0", "ge-0/0/3.2"),
			wantErr: "requires family inet dhcp",
		},
		{
			name:    "inet6 destination rejected",
			lines:   policy("::/0", "ge-0/0/3.0"),
			wantErr: "inet-only",
		},
		{
			name: "management interface rejected",
			lines: append(policy("0.0.0.0/0", "fxp0.0"),
				"set interfaces fxp0 unit 0 family inet dhcp"),
			wantErr: "management interface",
		},
		{
			// Codex PR #1851 review (Low): the interface compiler sets
			// unit.DHCP without an interface-class guard, so `family
			// inet dhcp` on a loopback unit DOES compile — the
			// validator must reject it by class, not rely on the
			// DHCP-flag check.
			name: "loopback interface rejected",
			lines: append(policy("0.0.0.0/0", "lo0.0"),
				"set interfaces lo0 unit 0 family inet dhcp"),
			wantErr: "tunnel or loopback interface",
		},
		{
			name: "gre tunnel interface rejected",
			lines: append(policy("0.0.0.0/0", "gr-0/0/0.0"),
				"set interfaces gr-0/0/0 unit 0 family inet dhcp"),
			wantErr: "tunnel or loopback interface",
		},
		{
			name: "ipsec st0 interface rejected",
			lines: append(policy("0.0.0.0/0", "st0.0"),
				"set interfaces st0 unit 0 family inet dhcp"),
			wantErr: "tunnel or loopback interface",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("CompileConfig succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestIPMonitoringInterfaceNextHopIdempotent: re-running the strict
// validator on an already-derived config must be a no-op (the derived
// NextHopInterface short-circuits; NextHop stays cleared).
func TestIPMonitoringInterfaceNextHopIdempotent(t *testing.T) {
	lines := append(rpmProbeLines(), dhcpUplinkLines()...)
	lines = append(lines,
		"set services ip-monitoring policy p match rpm-probe WAN",
		"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop ge-0/0/3.50",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if err := validateIPMonitoringStrict(cfg); err != nil {
		t.Fatalf("re-validation error: %v", err)
	}
	pr := cfg.Services.IPMonitoring.Policies["p"].PreferredRoutes[0]
	if pr.NextHopInterface != "ge-0-0-3.50" || pr.NextHop != "" {
		t.Fatalf("route after re-validation = %+v", pr)
	}
}

// TestDHCPLeaseIfName pins the shared helper directly.
func TestDHCPLeaseIfName(t *testing.T) {
	if got := DHCPLeaseIfName("ge-0/0/3", &InterfaceUnit{Number: 0}); got != "ge-0-0-3" {
		t.Fatalf("untagged = %q", got)
	}
	if got := DHCPLeaseIfName("ge-0/0/3", &InterfaceUnit{Number: 1, VlanID: 80}); got != "ge-0-0-3.80" {
		t.Fatalf("tagged = %q", got)
	}
	if got := DHCPLeaseIfName("reth0", nil); got != "reth0" {
		t.Fatalf("nil unit = %q", got)
	}
}
