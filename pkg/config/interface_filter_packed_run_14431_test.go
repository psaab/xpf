package config

import (
	"strings"
	"testing"
)

// #14431 (DR17-H2): interface `family inet/inet6 filter` packed run drops
// the SECOND direction.
//
// `family inet { filter input F-IN output F-OUT; }` packed both directions
// onto the filter node's Keys. compileInterfaces reads
// filterNode.FindChildren("input"/"output"), which saw nothing, so at best
// the first direction survived (via the compact normalizer's single-child
// fold, which lowered the run to `filter { [input F-IN output F-OUT] }` and
// nodeVal read only F-IN) and the second direction was silently dropped —
// the interface forwarded unfiltered in that direction on a clean commit.
// The #10293 gate also misread the run as a multi-value singular binding and
// strict-rejected it naming only the first direction.
//
// Fix: the interface filter container opts into packedStatements so the
// brace-elision / braced-packed splitter lowers the run to one
// [input F-IN] / [output F-OUT] statement per direction (both orders), and
// the #10293 multi-value check treats a direction keyword as a statement
// boundary rather than an extra value.
//
// Fail-on-revert: dropping `packedStatements` from either family filter in
// schema_interfaces.go (or reverting the #10293 boundary check) makes every
// packed cell below fail — strict either rejects (#10293) or compiles with
// the second direction empty, and lenient compiles with it empty.

func dirName14431(direction string) string {
	if direction == "input" {
		return "F-IN"
	}
	return "F-OUT"
}

func packedFilterFixture14431(t *testing.T, family, first, second string) *ConfigTree {
	t.Helper()
	src := "interfaces { ge-0/0/0 { unit 0 { family " + family + " { filter " +
		first + " " + dirName14431(first) + " " + second + " " + dirName14431(second) + "; } } } } " +
		"firewall { family " + family + " { filter F-IN { term t { then accept; } } " +
		"filter F-OUT { term t { then accept; } } } }"
	return hierTree(t, src)
}

func unitFilter14431(t *testing.T, cfg *Config, family string) (string, string) {
	t.Helper()
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil || iface.Units[0] == nil {
		t.Fatalf("ge-0/0/0 unit 0 missing: %+v", cfg.Interfaces.Interfaces)
	}
	u := iface.Units[0]
	if family == "inet6" {
		return u.FilterInputV6, u.FilterOutputV6
	}
	return u.FilterInputV4, u.FilterOutputV4
}

func TestInterfaceFilterPackedRunBothDirections14431(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, order := range [][2]string{{"input", "output"}, {"output", "input"}} {
			name := family + "/" + order[0] + "-first"
			t.Run(name, func(t *testing.T) {
				cfg, err := CompileConfig(packedFilterFixture14431(t, family, order[0], order[1]))
				if err != nil {
					t.Fatalf("strict packed two-direction filter must commit: %v", err)
				}
				in, out := unitFilter14431(t, cfg, family)
				if in != "F-IN" || out != "F-OUT" {
					t.Fatalf("strict packed run lost a direction: input=%q output=%q, want F-IN/F-OUT", in, out)
				}
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "#10293") || strings.Contains(w, "#12090") {
						t.Fatalf("supported packed run drew a diagnostic: %q", w)
					}
				}
				cfgL, err := CompileConfigLenient(packedFilterFixture14431(t, family, order[0], order[1]))
				if err != nil {
					t.Fatalf("lenient packed two-direction filter must compile: %v", err)
				}
				inL, outL := unitFilter14431(t, cfgL, family)
				if inL != "F-IN" || outL != "F-OUT" {
					t.Fatalf("lenient packed run lost a direction: input=%q output=%q, want F-IN/F-OUT", inL, outL)
				}
			})
		}
	}
}

func TestInterfaceFilterPackedFamilyRunBothDirections14431(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family, func(t *testing.T) {
			src := "interfaces { ge-0/0/0 { unit 0 { family " + family + " filter input F-IN output F-OUT; } } } " +
				"firewall { family " + family + " { filter F-IN { term t { then accept; } } " +
				"filter F-OUT { term t { then accept; } } } }"
			cfg, err := CompileConfig(hierTree(t, src))
			if err != nil {
				t.Fatalf("strict family-packed run must commit: %v", err)
			}
			in, out := unitFilter14431(t, cfg, family)
			if in != "F-IN" || out != "F-OUT" {
				t.Fatalf("family-packed run lost a direction: input=%q output=%q, want F-IN/F-OUT", in, out)
			}
		})
	}
}

func TestInterfaceFilterPackedRunControls14431(t *testing.T) {
	t.Run("braced", func(t *testing.T) {
		src := "interfaces { ge-0/0/0 { unit 0 { family inet { filter { input F-IN; output F-OUT; } } } } } " +
			"firewall { family inet { filter F-IN { term t { then accept; } } filter F-OUT { term t { then accept; } } } }"
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("braced control must commit: %v", err)
		}
		in, out := unitFilter14431(t, cfg, "inet")
		if in != "F-IN" || out != "F-OUT" {
			t.Fatalf("braced control drifted: input=%q output=%q", in, out)
		}
	})
	t.Run("single-packed", func(t *testing.T) {
		src := "interfaces { ge-0/0/0 { unit 0 { family inet { filter input F-IN; } } } } " +
			"firewall { family inet { filter F-IN { term t { then accept; } } } }"
		cfg, err := CompileConfig(hierTree(t, src))
		if err != nil {
			t.Fatalf("single packed control must commit: %v", err)
		}
		in, out := unitFilter14431(t, cfg, "inet")
		if in != "F-IN" || out != "" {
			t.Fatalf("single packed control drifted: input=%q output=%q", in, out)
		}
	})
	t.Run("multi-value-still-rejected", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set firewall family inet filter f1 term t1 then accept",
			"set firewall family inet filter f2 term t1 then accept",
			"set interfaces ge-0/0/0 unit 0 family inet filter input f1 f2",
		)
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "#10293") {
			t.Fatalf("multi-value singular must still reject #10293, got: %v", err)
		}
	})
}
