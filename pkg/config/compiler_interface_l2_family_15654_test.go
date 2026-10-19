package config

import (
	"strings"
	"testing"
)

// #15654: L2 content under `family ethernet-switching` / `family bridge`
// (access/trunk VLAN configuration) and filter/policer/sample bindings
// under those families compiled to nothing on strict commit — only the
// generic #10707 advisory, or nothing at all for the braced bridge form.
// compileInterfaces builds only inet/inet6 units, so the gate in
// validateUnsupportedInterfaceStanzasAST now fails closed (strict) /
// warns (lenient) for that content, and policer bindings can no longer
// bypass #12656 by hiding under an L2 family.

func assertStrictReject15654(t *testing.T, tree *ConfigTree, want ...string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict compile must reject #15654 content %v", want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("strict error %q must contain %q", err, w)
		}
	}
}

func assertLenientWarns15654(t *testing.T, tree *ConfigTree, want ...string) {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot: %v", err)
	}
	for _, warning := range cfg.Warnings {
		if !strings.Contains(warning, "#15654") {
			continue
		}
		ok := true
		for _, w := range want {
			if !strings.Contains(warning, w) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("lenient warnings %q lack a #15654 warning containing %v", cfg.Warnings, want)
}

func TestL2FamilyContentRejected15654(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T) *ConfigTree
		want  []string
	}{
		{"es access hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { port-mode access; vlan { members 100; } } } } }")
		}, []string{"#15654", "ethernet-switching", "port-mode"}},
		{"es trunk hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { interface-mode trunk; vlan { members [ 100 200 ]; } } } } }")
		}, []string{"#15654", "ethernet-switching", "interface-mode"}},
		{"es access flat port-mode", func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode access")
		}, []string{"#15654", "ethernet-switching", "port-mode"}},
		{"es vlan members hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members 100; } } } } }")
		}, []string{"#15654", "ethernet-switching", "vlan members"}},
		{"es native vlan hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { native-vlan-id 10; } } } }")
		}, []string{"#15654", "ethernet-switching", "native-vlan-id"}},
		{"es vlan-id hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { interface-mode access; vlan-id 100; } } } }")
		}, []string{"#15654", "ethernet-switching"}},
		{"bridge vlan members hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family bridge { vlan { members 100; } } } } }")
		}, []string{"#15654", "bridge", "vlan members"}},
		{"bridge interface-mode hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family bridge { interface-mode trunk; vlan { members 100; } } } } }")
		}, []string{"#15654", "bridge", "interface-mode"}},
		{"split es trunk", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family { ethernet-switching { interface-mode trunk; vlan { members 100; } } } } } }")
		}, []string{"#15654", "ethernet-switching", "interface-mode"}},
		{"packed unit es trunk", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 family ethernet-switching { interface-mode trunk; vlan { members 100; } } } }")
		}, []string{"#15654", "ethernet-switching"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertStrictReject15654(t, tc.build(t), tc.want...)
			assertLenientWarns15654(t, tc.build(t), tc.want...)
		})
	}
}

func TestL2FamilyBindingsRejected15654(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*testing.T) *ConfigTree
		want  []string
	}{
		{"es policer flat", func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family ethernet-switching policer input p1")
		}, []string{"#15654", "ethernet-switching", "policer input"}},
		{"es policer hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { policer { input p1; } } } } }")
		}, []string{"#15654", "ethernet-switching", "policer input"}},
		{"bridge policer flat", func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family bridge policer output p1")
		}, []string{"#15654", "bridge", "policer output"}},
		{"es sample hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { sample { input; } } } } }")
		}, []string{"#15654", "ethernet-switching", "sample input"}},
		{"ccc policer flat", func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family ccc policer output p1")
		}, []string{"#15654", "ccc", "policer output"}},
		{"vpls policer hier", func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family vpls { policer { output p1; } } } } }")
		}, []string{"#15654", "vpls", "policer output"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertStrictReject15654(t, tc.build(t), tc.want...)
			assertLenientWarns15654(t, tc.build(t), tc.want...)
		})
	}
}

// The acceptance regression shape: trunk + members + a guard binding must
// never strict-commit as a warned no-op.
func TestL2TrunkWithFilterNeverWarnedNoOp15654(t *testing.T) {
	tree := hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { interface-mode trunk; vlan { members [ 100 200 ]; } filter { input f1; } } } } }")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict trunk+filter must be rejected, not committed as warned no-op")
	}
	tree = hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { interface-mode trunk; vlan { members [ 100 200 ]; } policer { input p1; } } } } }")
	assertStrictReject15654(t, tree, "#15654", "policer input")
}

// Filter under an L2 family keeps exactly the #12090 single-diagnostic
// contract on the lenient path (no duplicate #15654/#12656 warning).
func TestL2FilterSingleDiagnostic15654(t *testing.T) {
	for _, build := range []func(*testing.T) *ConfigTree{
		func(t *testing.T) *ConfigTree {
			return hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { filter { input f1; } } } } }")
		},
		func(t *testing.T) *ConfigTree {
			return flatTreeFromSets(t, "set interfaces ge-0/0/0 unit 0 family bridge filter input f1")
		},
	} {
		tree := build(t)
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "#12090") {
			t.Fatalf("strict L2 filter must reject with #12090, got %v", err)
		}
		cfg, err := CompileConfigLenient(build(t))
		if err != nil {
			t.Fatalf("lenient: %v", err)
		}
		var guard int
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "filter input") &&
				(strings.Contains(w, "#12090") || strings.Contains(w, "#12656") || strings.Contains(w, "#15654")) {
				guard++
			}
		}
		if guard != 1 {
			t.Fatalf("want exactly one filter diagnostic, got %d in %q", guard, cfg.Warnings)
		}
	}
}

// Controls: supported and bare shapes are untouched.
func TestL2FamilyControls15654(t *testing.T) {
	// Supported inet filter still commits and populates the typed hook.
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet filter input f1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set firewall family inet filter f1 term t then accept"))
	if u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]; u == nil || u.FilterInputV4 != "f1" {
		t.Fatalf("inet control lost its filter hook: %+v", u)
	}
	// Bare L2 / other-AF families with no authored content stay warn-only
	// (#15199 posture; no new strict rejection, no #15654 warning).
	for _, set := range []string{
		"set interfaces ge-0/0/0 unit 0 family bridge",
		"set interfaces ge-0/0/0 unit 0 family ethernet-switching",
		"set interfaces ge-0/0/0 unit 0 family mpls",
	} {
		cfg, err := CompileConfig(flatTreeFromSets(t, set))
		if err != nil {
			t.Fatalf("bare %q must remain warn-only: %v", set, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#15654") {
				t.Fatalf("bare %q drew a #15654 warning: %q", set, w)
			}
		}
	}
	// A VLAN member VALUE spelled `filter` must never be named by a
	// #15654 diagnostic (values are not keywords). The members content
	// itself is rejected, without leaking the value into the message.
	_, err := CompileConfig(hierTree(t, "interfaces { ge-0/0/0 { unit 0 { family ethernet-switching { vlan { members filter; } } } } }"))
	if err == nil {
		t.Fatal("vlan members content must be rejected")
	}
	if !strings.Contains(err.Error(), "#15654") || strings.Contains(err.Error(), "`filter`") {
		t.Fatalf("diagnostic must name #15654 without naming the member value: %v", err)
	}
	// Inactive L2 content is pruned before the gate and must not reject.
	assertCommitAccepts(t, hierTree(t, "interfaces { ge-0/0/0 { inactive: unit 0 { family ethernet-switching { interface-mode trunk; vlan { members 100; } } } unit 0 { family inet { address 10.0.0.1/24; } } } }"))
}
