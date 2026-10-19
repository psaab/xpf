package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderBGP15010(bgp *config.BGPConfig) string {
	return New().generateProtocols(nil, nil, bgp, nil, nil, "", 1, nil, nil)
}

// #15010: default Junos prefix-limit (maximum only) is log-only and must
// render FRR warning-only; bare maximum-prefix kills the session.
func TestBGPMaximumPrefixWarningOnlyDefault15010(t *testing.T) {
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000},
		{Address: "2001:db8::1", PeerAS: 65003, FamilyInet6: true, PrefixLimitInet6: 500},
	}}
	got := renderBGP15010(bgp)
	if !strings.Contains(got, "neighbor 192.0.2.1 maximum-prefix 1000 warning-only\n") {
		t.Fatalf("default inet must render warning-only:\n%s", got)
	}
	if !strings.Contains(got, "neighbor 2001:db8::1 maximum-prefix 500 warning-only\n") {
		t.Fatalf("default inet6 must render warning-only:\n%s", got)
	}
	if strings.Contains(got, "maximum-prefix 1000\n") || strings.Contains(got, "maximum-prefix 500\n") {
		t.Fatalf("bare hard maximum-prefix leaked:\n%s", got)
	}
}

func TestBGPMaximumPrefixTeardownForms15010(t *testing.T) {
	cases := []struct {
		name string
		n    *config.BGPNeighbor
		want string
	}{
		{"teardown bare", &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true}, "neighbor 192.0.2.1 maximum-prefix 1000\n"},
		{"teardown pct", &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true, PrefixLimitTeardownPctInet: 75}, "neighbor 192.0.2.1 maximum-prefix 1000 75\n"},
		{"teardown restart", &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true, PrefixLimitIdleTimeoutInet: 30}, "neighbor 192.0.2.1 maximum-prefix 1000 restart 30\n"},
		{"teardown pct+restart", &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true, PrefixLimitTeardownPctInet: 75, PrefixLimitIdleTimeoutInet: 30}, "neighbor 192.0.2.1 maximum-prefix 1000 75 restart 30\n"},
		{"teardown forever", &config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true, PrefixLimitIdleForeverInet: true}, "neighbor 192.0.2.1 maximum-prefix 1000\n"},
		{"teardown pct inet6", &config.BGPNeighbor{Address: "2001:db8::1", PeerAS: 65003, FamilyInet6: true, PrefixLimitInet6: 500, PrefixLimitTeardownInet6: true, PrefixLimitTeardownPctInet6: 50, PrefixLimitIdleTimeoutInet6: 10}, "neighbor 2001:db8::1 maximum-prefix 500 50 restart 10\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renderBGP15010(&config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{tc.n}})
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in:\n%s", tc.want, got)
			}
			if tc.name == "teardown bare" || tc.name == "teardown forever" {
				// No restart token in these forms; offender stays down
				// (FRR no-restart = manual clear; restart-form re-establishes).
				if strings.Contains(got, "restart") || strings.Contains(got, "warning-only") {
					t.Fatalf("%s must not carry restart/warning-only:\n%s", tc.name, got)
				}
			}
		})
	}
}

// Out-of-range typed values from tolerant construction must not reach vtysh.
func TestBGPMaximumPrefixTeardownBounds15010(t *testing.T) {
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 100, PrefixLimitTeardownInet: true, PrefixLimitTeardownPctInet: 101, PrefixLimitIdleTimeoutInet: 70000},
	}}
	got := renderBGP15010(bgp)
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "maximum-prefix") {
			if strings.Contains(line, " 101") || strings.Contains(line, "70000") {
				t.Fatalf("out-of-range teardown operand reached FRR: %q\n%s", line, got)
			}
		}
	}
}

// The produced forms must be accepted by the real FRR grammar (vtysh -C)
// and an invalid-keyword mutation rejected, proving the check reads input.
func TestBGPMaximumPrefixFormsAcceptedByFRR15010(t *testing.T) {
	vtysh := frrVtyshBinary12185(t)
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "192.0.2.1", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000},
		{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true, PrefixLimitInet: 1000, PrefixLimitTeardownInet: true, PrefixLimitTeardownPctInet: 75, PrefixLimitIdleTimeoutInet: 30},
		{Address: "2001:db8::1", PeerAS: 65003, FamilyInet6: true, PrefixLimitInet6: 500, PrefixLimitTeardownInet6: true},
	}}
	rendered := New().buildManagedSection(&FullConfig{BGP: bgp})
	for _, want := range []string{"maximum-prefix 1000 warning-only", "maximum-prefix 1000 75 restart 30", "maximum-prefix 500\n"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("fixture missing %q:\n%s", want, rendered)
		}
	}
	if out, err := validateRenderedRouting11417(t, vtysh, rendered); err != nil {
		t.Fatalf("FRR vtysh rejected teardown render: %v\n%s\n%s", err, out, rendered)
	}
	mutated := strings.Replace(rendered, "maximum-prefix 1000 warning-only", "maximum-prefix 1000 warning-onlyy", 1)
	if out, err := validateRenderedRouting11417(t, vtysh, mutated); err == nil {
		t.Fatalf("FRR accepted invalid warning-onlyy mutation; validator blind:\n%s", out)
	}
}

// End-to-end from operator spelling: Junos `maximum 1000` alone must stay
// log-only after compile+render, and `teardown 75 idle-timeout 30` must
// render the FRR threshold+restart form. This cell uses only string
// config, so it also fails by assertion (not just by build) pre-fix.
func TestBGPMaximumPrefixFromConfigSpelling15010(t *testing.T) {
	build := func(extra ...string) string {
		tree := &config.ConfigTree{}
		cmds := []string{
			"set protocols bgp local-as 65001",
			"set protocols bgp group external peer-as 65002",
			"set protocols bgp group external neighbor 192.0.2.1",
			"set protocols bgp group external neighbor 192.0.2.1 family inet unicast prefix-limit maximum 1000",
		}
		cmds = append(cmds, extra...)
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		if err := config.SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate: %v", err)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 1, nil, nil)
	}
	got := build()
	if !strings.Contains(got, "neighbor 192.0.2.1 maximum-prefix 1000 warning-only\n") {
		t.Fatalf("config default must render warning-only:\n%s", got)
	}
	got = build("set protocols bgp group external neighbor 192.0.2.1 family inet unicast prefix-limit teardown 75 idle-timeout 30")
	if !strings.Contains(got, "neighbor 192.0.2.1 maximum-prefix 1000 75 restart 30\n") {
		t.Fatalf("config teardown must render threshold+restart:\n%s", got)
	}
}
