package config

import (
	"strings"
	"testing"
)

// Issue 9023: a repeated named BLOCK discarded the earlier one.
//
// THE ASSERTION IS AGAINST THE MERGED SPELLING, not against a remembered
// number. `trap-group tg1 { targets X; } trap-group tg1 { version v1; }` must
// compile to exactly what `trap-group tg1 { targets X; version v1; }` compiles
// to — that is the property, and it stays true if either side's defaults move.

type dupBlockCase9023 struct {
	name   string
	twoBlk string
	merged string // the SAME configuration written once
	read   func(*Config) string
}

func dupBlockCases9023() []dupBlockCase9023 {
	return []dupBlockCase9023{
		{
			name:   "snmp trap-group",
			twoBlk: "snmp {\n trap-group tg1 { targets 10.0.0.1; }\n trap-group tg1 { version v1; }\n}",
			merged: "snmp {\n trap-group tg1 { targets 10.0.0.1; version v1; }\n}",
			read: func(c *Config) string {
				if c.System.SNMP == nil {
					return "<no snmp>"
				}
				var b strings.Builder
				for _, g := range c.System.SNMP.TrapGroups {
					b.WriteString(g.Name + " targets=" + strings.Join(g.Targets, ",") + " version=" + g.Version + ";")
				}
				return b.String()
			},
		},
		{
			name: "forwarding-options sampling instance",
			twoBlk: "forwarding-options {\n sampling {\n  instance i1 { input { rate 100; } }\n" +
				"  instance i1 { family inet { output { flow-server 10.0.0.1 { port 2055; } } } }\n }\n}",
			merged: "forwarding-options {\n sampling {\n  instance i1 { input { rate 100; }" +
				" family inet { output { flow-server 10.0.0.1 { port 2055; } } } }\n }\n}",
			read: func(c *Config) string {
				if c.ForwardingOptions.Sampling == nil {
					return "<no sampling>"
				}
				var b strings.Builder
				for _, in := range c.ForwardingOptions.Sampling.Instances {
					b.WriteString(in.Name + " rate=" + itoa9023(in.InputRate) + " inet=" + boolStr9023(in.FamilyInet != nil) + ";")
				}
				return b.String()
			},
		},
	}
}

func boolStr9023(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func itoa9023(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func compile9023(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("lenient compile failed for %q: %v", text, err)
	}
	return cfg
}

func TestDuplicateBlocksConserve9023(t *testing.T) {
	for _, c := range dupBlockCases9023() {
		t.Run(c.name, func(t *testing.T) {
			want := c.read(compile9023(t, c.merged))
			// LIVENESS: the merged reference must carry real values, or the
			// comparison below passes against two empty strings. This is the
			// check that would have caught a fixture whose container never
			// compiled at all.
			if want == "" || strings.HasPrefix(want, "<no ") {
				t.Fatalf("the merged reference compiled to %q — every comparison against it is vacuous", want)
			}
			if got := c.read(compile9023(t, c.twoBlk)); got != want {
				t.Errorf("two blocks of the same name do not compile to the merged spelling.\n"+
					" merged:     %s\n two blocks: %s\n"+
					"The later block replaced the earlier one and its configuration was discarded", want, got)
			}
		})
	}
}

// The STRICT path must accept the two-block spelling too. Before this change
// `snmp trap-group` was rejected there — but for an unrelated reason: the
// zero-target gate (#2990) runs per BLOCK, so the `version v1` block tripped it
// alone and the operator who wrote `targets 10.0.0.1` was told "no targets
// configured". That diagnostic was true about a block they did not intend to
// exist, and it described a symptom of the duplication rather than the
// duplication.
// MUTATION NOTE: unwiring the merge reds the `snmp trap-group` row here and
// NOT the `sampling instance` row -- sampling was always accepted strictly, so
// that subtest documents a pre-existing fact rather than binding this change.
// It is kept because a future gate that started rejecting the two-block
// spelling would be a regression, but it should not be read as coverage of the
// merge.
func TestDuplicateBlocksAcceptedStrictly9023(t *testing.T) {
	for _, c := range dupBlockCases9023() {
		t.Run(c.name, func(t *testing.T) {
			tree, _ := NewParser(c.twoBlk).Parse()
			if _, err := compileTree(tree, compileOpts{}, nil); err != nil {
				t.Errorf("the strict path rejected the two-block spelling: %v\n"+
					"After merging, the surviving block carries what the operator wrote, so a "+
					"gate firing here is reporting a symptom of the duplication", err)
			}
		})
	}
}

// The merge is ANNOUNCED. A config whose meaning changes should say so even
// when the new meaning is the intended one.
func TestDuplicateBlockMergeWarns9023(t *testing.T) {
	for _, c := range dupBlockCases9023() {
		t.Run(c.name, func(t *testing.T) {
			tree, _ := NewParser(c.twoBlk).Parse()
			cfg, err := CompileConfigLenient(tree)
			if err != nil || cfg == nil {
				t.Fatalf("compile: %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "duplicate block") && strings.Contains(w, "9023") {
					found = true
				}
			}
			if !found {
				t.Errorf("merging produced no warning; the operator's configuration changed "+
					"meaning silently. warnings=%v", cfg.Warnings)
			}
		})
	}
}

// NON-VACUITY on the site list: a container NOT on the list must be unaffected,
// so the merge cannot be passing by rewriting everything.
func TestUnlistedContainerIsUntouched9023(t *testing.T) {
	const text = "security {\n zones {\n  security-zone z1 { description a; }\n  security-zone z1 { description b; }\n }\n}"
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs[0])
	}
	before := tree.Format()
	if n := mergeDuplicateBlocks9023(tree); len(n) != 0 {
		t.Errorf("merged %v, but security-zone is not on dupBlockMergeSites9023 — the walk is "+
			"not honouring its site list", n)
	}
	if tree.Format() != before {
		t.Error("the tree was modified for a container that is not on the site list")
	}
}
