package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15199 — commit-validation reference/open-world gaps (A05-03/06/07).

func cohortWarningsContain15199(warnings []string, subs ...string) bool {
	for _, w := range warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// A05-03: reth RG with no chassis RG definition must strict-reject, lenient-warn.
func TestRethUndefinedRG15199(t *testing.T) {
	base := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15199",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth5",
		"set interfaces reth5 redundant-ether-options redundancy-group 5",
		"set interfaces reth5 unit 0 family inet address 10.0.95.1/24",
	}
	if _, err := CompileConfig(buildTree(t, base)); err == nil {
		t.Fatal("strict: undefined RG5 must reject")
	} else if !strings.Contains(err.Error(), "reth5") || !strings.Contains(err.Error(), "redundancy-group 5") {
		t.Fatalf("error %q must name reth5/RG5", err)
	}
	lcfg, err := CompileConfigLenient(buildTree(t, base))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	if !warningsContain(lcfg.Warnings, "redundancy-group 5") {
		t.Fatalf("lenient must warn RG5; %v", lcfg.Warnings)
	}
	// Control: define RG5 -> commits.
	defined := append(append([]string{}, base...),
		"set chassis cluster redundancy-group 5 node 0 priority 200",
		"set chassis cluster redundancy-group 5 node 1 priority 100")
	// RG5 exceeds? RG ids <16 ok, derived VRID 105 ok.
	if _, err := CompileConfig(buildTree(t, defined)); err != nil {
		t.Fatalf("control defined RG5 must commit: %v", err)
	}
	// Control: standalone (no cluster) reth without chassis RG commits.
	solo := []string{
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	}
	if _, err := CompileConfig(buildTree(t, solo)); err != nil {
		t.Fatalf("standalone control must commit: %v", err)
	}
	// Control: defined RG1 on reth (6781 fixtures) commits.
	rg1 := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15199",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	}
	if _, err := CompileConfig(buildTree(t, rg1)); err != nil {
		t.Fatalf("defined RG1 control must commit: %v", err)
	}
}

// A05-06: unknown interface keywords warn on both paths, known stay silent.
func TestInterfacesOpenWorldWarn15199(t *testing.T) {
	cases := []struct {
		name, want string
		lines      []string
	}{
		{"ether-options", "ether-options", []string{"set interfaces ge-0/0/1 ether-options 802.3ad ae0", "set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24"}},
		{"family bridge", "bridge", []string{"set interfaces ge-0/0/1 unit 0 family bridge"}},
		{"arbitrary", "zzbogus", []string{"set interfaces ge-0/0/1 unit 0 zzbogus 1"}},
		{"filtr typo", "filtr", []string{"set interfaces ge-0/0/1 unit 0 family inet filtr input f1", "set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("warn-only, must commit: %v", err)
			}
			if !cohortWarningsContain15199(cfg.Warnings, "#10707", tc.want) && !cohortWarningsContain15199(cfg.Warnings, "#15199", tc.want) && !warningsContain(cfg.Warnings, tc.want) {
				t.Fatalf("must warn %q; warnings=%v", tc.want, cfg.Warnings)
			}
			// specifically #10707 advisory
			if !cohortWarningsContain15199(cfg.Warnings, "#10707") {
				t.Fatalf("must carry #10707 advisory; %v", cfg.Warnings)
			}
			lcfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			if !cohortWarningsContain15199(lcfg.Warnings, "#10707") {
				t.Fatalf("lenient must warn #10707; %v", lcfg.Warnings)
			}
		})
	}
	// Hier spelling
	hier := "interfaces { ge-0/0/1 { ether-options { 802.3ad ae0; } unit 0 { family inet { address 10.0.1.1/24; } } } }"
	cfg, err := CompileConfig(parseHier(t, hier))
	if err != nil {
		t.Fatalf("hier: %v", err)
	}
	if !cohortWarningsContain15199(cfg.Warnings, "#10707", "ether-options") {
		t.Fatalf("hier ether-options must warn #10707; %v", cfg.Warnings)
	}
	// Controls: supported config must not carry #10707 interface warnings for these keywords.
	controls := [][]string{
		{"set interfaces ge-0/0/1 gigether-options 802.3ad ae0"},
		{"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24"},
		{"set interfaces ge-0/0/1 unit 0 family inet filter input f1", "set firewall family inet filter f1 term t then accept"},
	}
	for i, lines := range controls {
		cfg, err := CompileConfig(buildTree(t, lines))
		if err != nil {
			t.Fatalf("control %d: %v", i, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#10707") && strings.Contains(w, "interfaces") {
				t.Fatalf("control %d unexpected #10707 interface warning %q", i, w)
			}
		}
	}
	// filtr control: FilterInput stays empty (document fail-open shape now warned)
	cfgF, _ := CompileConfig(buildTree(t, []string{"set interfaces ge-0/0/1 unit 0 family inet filtr input f1", "set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24"}))
	if u := cfgF.Interfaces.Interfaces["ge-0/0/1"].Units[0]; u.FilterInputV4 != "" {
		t.Fatalf("filtr must not populate FilterInputV4, got %q", u.FilterInputV4)
	}
}

// A05-07: Junos vrrp-inet6-group compiles to same VRRPGroup as xpf spelling.
func TestVRRPInet6JunosSpelling15199(t *testing.T) {
	junosFlat := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 priority 150",
	}
	xpfFlat := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 virtual-address 2001:db8::1/64",
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-group 1 priority 150",
	}
	get := func(lines []string) *VRRPGroup {
		cfg, err := CompileConfig(buildTree(t, lines))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64")
	}
	jg, xg := get(junosFlat), get(xpfFlat)
	if jg == nil || xg == nil {
		t.Fatalf("both spellings must compile VIP: junos=%v xpf=%v", jg, xg)
	}
	if !reflect.DeepEqual(jg, xg) {
		t.Fatalf("Junos spelling must equal xpf VRRPGroup:\njunos=%+v\nxpf=%+v", jg, xg)
	}
	// Hierarchical Junos
	hierJunos := "interfaces { reth0 { unit 0 { family inet6 { address 2001:db8::10/64 { vrrp-inet6-group 1 { virtual-inet6-address 2001:db8::1/64; priority 150; } } } } } }"
	cfg, err := CompileConfig(parseHier(t, hierJunos))
	if err != nil {
		t.Fatalf("hier Junos: %v", err)
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64"); vg == nil || vg.Priority != 150 {
		t.Fatalf("hier Junos VIP/priority wrong: %+v", vg)
	}
	// Unknown child inside Junos group still rejects (#15046 extension)
	bad := []string{
		"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 zzbogus 1",
	}
	if _, err := CompileConfig(buildTree(t, bad)); err == nil {
		t.Fatal("zzbogus inside vrrp-inet6-group must reject")
	}
	// Invalid VIP under Junos spelling must not silently compile (schema/commit gate catches via same group)
	// Lenient still compiles Junos spelling
	lcfg, err := CompileConfigLenient(buildTree(t, junosFlat))
	if err != nil {
		t.Fatalf("lenient Junos: %v", err)
	}
	if firstVRRPGroupWithVIP(t, lcfg, "2001:db8::1/64") == nil {
		t.Fatal("lenient Junos must compile VIP")
	}
}
