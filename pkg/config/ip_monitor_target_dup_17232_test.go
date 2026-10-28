package config

import (
	"strings"
	"testing"
)

// #17232 (R4-Q23-03): the #15038 probe-binding reader ipMonitorTargetProp
// cloned the #6588 first-wins weight reader without the duplicate gate that
// makes first-wins safe. A duplicate `interface` / `secondary-ip-address` on
// one ip-monitoring target compiled spelling-dependently with no diagnostic:
// braced duplicates picked the first child leaf, packed duplicates picked the
// first inline token, and nothing rejected either.
//
// Fix: monitorWeightTokens is generalised to monitorEntryAttrTokens(entry,
// kw), ipMonitorTargetProp is deleted, and the gate loops over the shared
// monitorAttrKeywords slice — so every attribute the compiler reads
// first-wins is duplicate-gated from one source of truth.
//
// FAIL-ON-REVERT: restore ipMonitorTargetProp and the weight-only gate loop
// and every Strict subtest below compiles clean again; the Tolerant subtest
// finds no warning.

// TestIPMonitorTargetDuplicateRejected_17232 pins strict rejection of a
// duplicated probe binding in every spelling the issue measured.
func TestIPMonitorTargetDuplicateRejected_17232(t *testing.T) {
	cases := []struct {
		name    string
		rgBody  string
		subject string
	}{
		{
			name: "BracedDupInterface",
			rgBody: "            ip-monitoring {\n" +
				"                family inet {\n" +
				"                    10.0.0.1 {\n" +
				"                        interface reth0.0;\n" +
				"                        interface reth1.0;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
			subject: "interface specified 2 times with different values",
		},
		{
			name:    "PackedDupInterface",
			rgBody:  "            ip-monitoring family inet 10.0.0.1 interface reth0.0 interface reth1.0;",
			subject: "interface specified 2 times with different values",
		},
		{
			name: "BracedDupSecondary",
			rgBody: "            ip-monitoring {\n" +
				"                family inet {\n" +
				"                    10.0.0.1 {\n" +
				"                        secondary-ip-address 10.0.1.5;\n" +
				"                        secondary-ip-address 10.0.1.6;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
			subject: "secondary-ip-address specified 2 times with different values",
		},
		{
			name: "InlineAndBracedInterface",
			rgBody: "            ip-monitoring {\n" +
				"                family inet {\n" +
				"                    10.0.0.1 interface reth0.0 {\n" +
				"                        interface reth1.0;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
			subject: "interface specified 2 times with different values",
		},
		{
			name:    "IdenticalRepeatInterface",
			rgBody:  "            ip-monitoring family inet 10.0.0.1 interface reth0.0 interface reth0.0;",
			subject: "interface specified 2 times",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := compileMonitorTextErr(t, packedMonitorConfig(tc.rgBody))
			assertErrContains(t, err, tc.subject)
			if strings.Contains(tc.subject, "different values") {
				return
			}
			if err != nil && strings.Contains(err.Error(), "different values") {
				t.Fatalf("error %q claims differing values for an identical repeat", err)
			}
		})
	}
}

// TestIPMonitorTargetDuplicateTolerantNoBrick_17232 pins the #1960 posture:
// an already-persisted or peer-synced config carrying a duplicate binding
// must still BOOT, with a warning, and the compiler keeps its first-wins pick.
func TestIPMonitorTargetDuplicateTolerantNoBrick_17232(t *testing.T) {
	p := NewParser(packedMonitorConfig(
		"            ip-monitoring family inet 10.0.0.1 interface reth0.0 interface reth1.0 secondary-ip-address 10.0.1.5;"))
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject a duplicate binding (no-brick), got %v", err)
	}
	if !warningsContain(cfg.Warnings, "interface specified 2 times with different values") {
		t.Fatalf("lenient compile should have warned; warnings=%v", cfg.Warnings)
	}
	rg := onlyRG6588(t, cfg)
	if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
		t.Fatalf("targets = %+v, want one target", rg.IPMonitoring)
	}
	tg := rg.IPMonitoring.Targets[0]
	if tg.Interface != "reth0.0" || tg.SecondaryIPAddress != "10.0.1.5" {
		t.Fatalf("target = %+v, want first-wins interface reth0.0 secondary 10.0.1.5", tg)
	}
}

// TestIPMonitorTargetSingleBindingStillCommits_17232 is the negative
// control: one binding of each kind, in either location and with a weight,
// must still commit and compile verbatim. Green with and without the gate.
func TestIPMonitorTargetSingleBindingStillCommits_17232(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rgBody string
	}{
		{
			name:   "Packed",
			rgBody: "            ip-monitoring family inet 10.0.0.1 weight 100 interface reth0.0 secondary-ip-address 10.0.1.5;",
		},
		{
			name: "Braced",
			rgBody: "            ip-monitoring {\n" +
				"                family inet {\n" +
				"                    10.0.0.1 {\n" +
				"                        weight 100;\n" +
				"                        interface reth0.0;\n" +
				"                        secondary-ip-address 10.0.1.5;\n" +
				"                    }\n" +
				"                }\n" +
				"            }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rg := compileMonitorText(t, packedMonitorConfig(tc.rgBody))
			if rg.IPMonitoring == nil || len(rg.IPMonitoring.Targets) != 1 {
				t.Fatalf("targets = %+v, want one target", rg.IPMonitoring)
			}
			tg := rg.IPMonitoring.Targets[0]
			if tg.Address != "10.0.0.1" || tg.Weight != 100 ||
				tg.Interface != "reth0.0" || tg.SecondaryIPAddress != "10.0.1.5" {
				t.Fatalf("target = %+v, want 10.0.0.1 weight 100 interface reth0.0 secondary 10.0.1.5", tg)
			}
		})
	}
}

// TestMonitorAttrKeywordsSingleSource_17232 pins the single source of truth
// the fix direction requires: the keyword slice the gate loops over is
// exactly the set isMonitorAttrKeyword encodes — so a future attribute
// cannot be recognised by the splitter (and read first-wins by the
// compiler) without also being duplicate-gated.
func TestMonitorAttrKeywordsSingleSource_17232(t *testing.T) {
	if len(monitorAttrKeywords) == 0 {
		t.Fatal("monitorAttrKeywords is empty")
	}
	seen := make(map[string]bool, len(monitorAttrKeywords))
	for _, kw := range monitorAttrKeywords {
		if seen[kw] {
			t.Fatalf("monitorAttrKeywords lists %q twice", kw)
		}
		seen[kw] = true
		if !isMonitorAttrKeyword(kw) {
			t.Fatalf("isMonitorAttrKeyword(%q) = false, want true (gate/splitter drift)", kw)
		}
		// The reader the gate checks must be the reader specialised from
		// the same generalised helper.
		entry := &Node{Keys: []string{"10.0.0.1", kw, "v1", kw, "v2"}}
		if got := monitorEntryAttrTokens(entry, kw); len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
			t.Fatalf("monitorEntryAttrTokens(%q) = %q, want [v1 v2]", kw, got)
		}
	}
	if !seen[monitorWeightKeyword] {
		t.Fatal("monitorAttrKeywords must include the weight keyword")
	}
	if got := monitorWeightTokens(&Node{Keys: []string{"ge-0/0/0", "weight", "7"}}); len(got) != 1 || got[0] != "7" {
		t.Fatalf("monitorWeightTokens = %q, want [7] (wrapper drifted from generalised reader)", got)
	}
}
