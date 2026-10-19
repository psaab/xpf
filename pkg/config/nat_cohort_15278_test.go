package config

import (
	"strings"
	"testing"
)

// #15278 cohort: D02-01..D02-04.

func nat64NoPrefixTree15278(t *testing.T) *ConfigTree {
	t.Helper()
	return buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
}

func TestNAT64NoPrefixStrictRejected15278(t *testing.T) {
	_, err := CompileConfig(nat64NoPrefixTree15278(t))
	if err == nil {
		t.Fatal("strict must reject NAT64 rule-set with no prefix")
	}
	if !strings.Contains(err.Error(), "rs1") || !strings.Contains(err.Error(), "no prefix") {
		t.Fatalf("error must name rule-set and missing prefix, got: %v", err)
	}
}

func TestNAT64NoPrefixLenientWarns15278(t *testing.T) {
	cfg, err := CompileConfigLenient(nat64NoPrefixTree15278(t))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "rs1") && strings.Contains(w, "prefix") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming rs1/prefix, warnings=%v", cfg.Warnings)
	}
}

func TestNAT64WithPrefixControl15278(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("ctl-prefix control must compile: %v", err)
	}
}

func natScopeBase15278() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat source pool pool1 address 192.0.2.10/32",
		"set security nat destination pool P1 address 10.0.30.100/32",
	}
}

func compileStrict15278(t *testing.T, cmds []string) error {
	t.Helper()
	_, err := CompileConfig(buildTree(t, cmds))
	return err
}

func TestNATUndefinedInterfaceRIScopeStrict15278(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{"source from-interface", append(natScopeBase15278(),
			"set security nat source rule-set snat-bad from interface ge-0/0/9.0",
			"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1"), "ge-0/0/9.0"},
		{"source to-interface", append(natScopeBase15278(),
			"set security nat source rule-set snat-bad to interface ge-0/0/9.0",
			"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1"), "ge-0/0/9.0"},
		{"source from-routing-instance", append(natScopeBase15278(),
			"set security nat source rule-set snat-bad from routing-instance nosuch",
			"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1"), "nosuch"},
		{"source to-routing-instance", append(natScopeBase15278(),
			"set security nat source rule-set snat-bad to routing-instance nosuch",
			"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1"), "nosuch"},
		{"destination from-interface", append(natScopeBase15278(),
			"set security nat destination rule-set dnat-bad from interface ge-0/0/9.0",
			"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
			"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1"), "ge-0/0/9.0"},
		{"destination from-routing-instance", append(natScopeBase15278(),
			"set security nat destination rule-set dnat-bad from routing-instance nosuch",
			"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
			"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1"), "nosuch"},
		{"static from-interface", append(natScopeBase15278(),
			"set security nat static rule-set stat-bad from interface ge-0/0/9.0",
			"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
			"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32"), "ge-0/0/9.0"},
		{"static from-routing-instance", append(natScopeBase15278(),
			"set security nat static rule-set stat-bad from routing-instance nosuch",
			"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
			"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32"), "nosuch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := compileStrict15278(t, tc.cmds)
			if err == nil {
				t.Fatalf("strict must reject undefined interface/RI scope %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestNATDefinedInterfaceRIScopeControl15278(t *testing.T) {
	cases := [][]string{
		append(natScopeBase15278(),
			"set security nat source rule-set snat-ok from interface ge-0/0/0.0",
			"set security nat source rule-set snat-ok to interface ge-0/0/1.0",
			"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1"),
		append(natScopeBase15278(),
			"set security nat source rule-set snat-ok from routing-instance blue",
			"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1"),
		append(natScopeBase15278(),
			"set security nat source rule-set snat-ok to routing-instance default",
			"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1"),
		append(natScopeBase15278(),
			"set interfaces lo0 unit 0 family inet address 127.0.0.1/32",
			"set security nat source rule-set snat-ok from interface lo0.0",
			"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
			"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1"),
	}
	for i, cmds := range cases {
		if err := compileStrict15278(t, cmds); err != nil {
			t.Fatalf("control %d must compile strict: %v", i, err)
		}
		cfg, err := CompileConfigLenient(buildTree(t, cmds))
		if err != nil {
			t.Fatalf("control %d lenient: %v", i, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "snat-ok") && strings.Contains(w, "not defined") {
				t.Fatalf("control %d must not warn undefined scope: %q", i, w)
			}
		}
	}
}

func TestNATUndefinedInterfaceRILenientWarns15278(t *testing.T) {
	cmds := append(natScopeBase15278(),
		"set security nat source rule-set snat-bad from interface ge-0/0/9.0",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snat-bad") && strings.Contains(w, "ge-0/0/9.0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming snat-bad/ge-0/0/9.0, warnings=%v", cfg.Warnings)
	}
	if len(cfg.LenientNATUndefinedScopeRuleSets) == 0 {
		t.Fatalf("lenient must record undefined-scope rule-sets for dataplane skip")
	}
}

func TestStaticNATHierRoutingInstance15278(t *testing.T) {
	for _, tc := range []struct{ name, txt string }{
		{"prefix hier", "security {\n nat {\n static {\n rule-set S {\n rule R1 {\n match { destination-address 203.0.113.5/32; }\n then { static-nat { prefix { 10.0.0.5/32; routing-instance VR; } } }\n }\n }\n }\n }\n}\n"},
		{"prefix-name hier", "security {\n address-book { global { address INSIDE 10.0.0.9/32; } }\n nat {\n static {\n rule-set S {\n rule R1 {\n match { destination-address 203.0.113.5/32; }\n then { static-nat { prefix-name { INSIDE; routing-instance VR; } } }\n }\n }\n }\n }\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, _ := NewParser(tc.txt).Parse()
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.ThenRoutingInstance != "VR" {
				t.Fatalf("ThenRoutingInstance=%q want VR", rule.ThenRoutingInstance)
			}
			found := false
			for _, w := range append(cfg.Warnings, ValidateConfig(cfg)...) {
				if strings.Contains(w, "VR") && strings.Contains(w, "4292") {
					found = true
				}
			}
			if !found {
				t.Fatalf("must emit #4292 advisory for VR, warnings=%v validate=%v", cfg.Warnings, ValidateConfig(cfg))
			}
		})
	}
	tree, _ := NewParser("security { nat { static { rule-set S { rule R1 { match { destination-address 203.0.113.5/32; } then { static-nat prefix 10.0.0.5/32 routing-instance VR; } } } } } }").Parse()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat control: %v", err)
	}
	if cfg.Security.NAT.Static[0].Rules[0].ThenRoutingInstance != "VR" {
		t.Fatalf("flat control tri=%q want VR", cfg.Security.NAT.Static[0].Rules[0].ThenRoutingInstance)
	}
}

func TestBareSecondPoolRejected15278(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"dest pool A B", natDupPoolSet7013("set security nat destination rule-set rs1 rule r1 then destination-nat pool PD PD2")},
		{"dest pool bracket", natDupPoolSet7013("set security nat destination rule-set rs1 rule r1 then destination-nat pool [ PD PD2 ]")},
		{"source pool A B", []string{
			"set security zones security-zone untrust",
			"set security nat source pool PS address 10.0.0.5",
			"set security nat source pool PS2 address 10.0.0.6",
			"set security nat source rule-set rs1 from zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.1.0/24",
			"set security nat source rule-set rs1 rule r1 then source-nat pool PS PS2",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.cmds))
			if err == nil {
				t.Fatal("bare second pool must be strict-rejected")
			}
			if !strings.Contains(err.Error(), "PD2") && !strings.Contains(err.Error(), "PS2") {
				t.Fatalf("error must name second pool, got: %v", err)
			}
		})
	}
	_, err := CompileConfig(buildTree(t, natDupPoolSet7013("set security nat destination rule-set rs1 rule r1 then destination-nat pool PD NOPE")))
	if err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("undefined bare second pool must reject naming NOPE, got: %v", err)
	}
	txt := "security {\n zones { security-zone untrust; }\n nat {\n destination {\n pool PD { address 10.0.0.5; }\n pool PD2 { address 10.0.0.6; }\n rule-set rs1 {\n from zone untrust;\n rule r1 {\n match { destination-address 203.0.113.10; }\n then { destination-nat { pool { PD; PD2; } } }\n }\n }\n }\n }\n}\n"
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("parse: %v", perr)
	}
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "PD2") {
		t.Fatalf("hier pool {PD; PD2;} must reject naming PD2, got: %v", err)
	}
}

func TestBarePoolControls15278(t *testing.T) {
	cmds := []string{
		"set security zones security-zone untrust",
		"set security nat source pool off address 10.0.0.9",
		"set security nat source rule-set rs1 from zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.1.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool off",
	}
	if _, err := CompileConfig(buildTree(t, cmds)); err != nil {
		t.Fatalf("pool off (single pool named off) must compile: %v", err)
	}
	txt := "security {\n zones { security-zone untrust; }\n nat {\n source {\n pool PS { address 10.0.0.5; }\n rule-set rs1 {\n from zone untrust;\n rule r1 {\n match { source-address 10.0.1.0/24; }\n then { source-nat { pool { PS; persistent-nat { permit any-remote-host; } } } }\n }\n }\n }\n }\n}\n"
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("parse persistent: %v", perr)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("pool {PS; persistent-nat} must compile: %v", err)
	}
}
