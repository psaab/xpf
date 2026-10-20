package config

import (
	"strings"
	"testing"
)

// #15935 regression bundle: ledger probes from waver-glm-cfg M1,
// waver-opus-cfg CFG-RETRO-1/2, GLM OSPF minor. Each test is RED on the
// pre-fix behaviour described in the issue.

// (1) Grouped `port range 5000 to 6000` + trailing modifier must keep
// the valid range, not fabricate "<empty>".
func TestGroupedRangePlusRandomAllocation15935(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 5000 to 6000",
		"set security nat source pool p1 port random-allocation")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile range+random-allocation: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortRangeInvalidSpec != "" {
		t.Fatalf("PortRangeInvalidSpec = %q, want empty (valid range clobbered)", pool.PortRangeInvalidSpec)
	}
	if pool.PortLow != 5000 || pool.PortHigh != 6000 {
		t.Fatalf("range = %d-%d, want 5000-6000", pool.PortLow, pool.PortHigh)
	}
	if !pool.PortRandomAllocation {
		t.Fatalf("random-allocation lost")
	}
}

func TestGroupedRangePlusNoTranslation15935(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range 5000 to 6000",
		"set security nat source pool p1 port no-translation")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortRangeInvalidSpec == "<empty>" {
		t.Fatalf("fabricated <empty> invalid spec clobbers grouped range")
	}
	if !pool.PortNoTranslation {
		t.Fatalf("no-translation cleared by trailing setPortRange(nil)")
	}
}

// Control: genuinely empty grouped range still fails closed.
func TestGroupedEmptyRangeStillFails15935(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.5/32",
		"set security nat source pool p1 port range")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("empty range must still reject strict")
	}
}

// (2) Annotation change on one block must not suppress a changed
// sibling block in FormatCompare.
func TestAnnotationCompareKeepsSiblingChange15935(t *testing.T) {
	parse := func(route string) *ConfigTree {
		tree, errs := NewParser("system {\n services { ssh { root-login allow; } }\n routing-options { static { route 10.0.0.0/8 " + route + "; } }\n}\n").Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	}
	oldT := parse("discard")
	newT := parse("reject")
	oldT.Children[0].Children[0].Annotation = "old note"
	newT.Children[0].Children[0].Annotation = "new note"
	diff := FormatCompare(oldT, newT)
	if !strings.Contains(diff, "/* new note */") {
		t.Fatalf("annotation delta missing:\n%s", diff)
	}
	if !strings.Contains(diff, "reject") {
		t.Fatalf("sibling routing-options change suppressed by annotation fallback:\n%s", diff)
	}
}

// Control: annotation-only compare still renders only the annotation.
func TestAnnotationOnlyCompare15935(t *testing.T) {
	a := annotatedTree15718(t)
	b := a.Clone()
	if err := b.AnnotatePath([]string{"system", "host-name"}, "secondary fw"); err != nil {
		t.Fatal(err)
	}
	if diff := FormatCompare(a, b); !strings.Contains(diff, "secondary fw") {
		t.Fatalf("annotation-only diff missing:\n%s", diff)
	}
	if diff := FormatCompare(a, a.Clone()); diff != "" {
		t.Fatalf("identical trees diff = %q, want empty", diff)
	}
}

// (3) Equivalent CIDR spellings merge into one RAPrefix.
func TestRAPrefixCanonicalDedup15935(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 { valid-lifetime 100; preferred-lifetime 50; }
            prefix 2001:0db8:0:0::/64 { no-autonomous; }
        }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false,
		ValidLifetime: 100, PreferredLife: 50, PreferredLifeSet: true,
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	// Host-bits spelling canonicalises by masked identity.
	tree2 := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::1/64 { valid-lifetime 100; }
            prefix 2001:db8::/64 { no-autonomous; }
        }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree2, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false, ValidLifetime: 100,
	})
	// Distinct CIDRs stay distinct.
	tree3 := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 { }
            prefix 2001:db8:0:1::/64 { }
        }
    }
}`)
	if n := len(raPrefixes15696(t, tree3, "ge-0/0/0.0")); n != 2 {
		t.Fatalf("distinct prefixes merged: got %d, want 2", n)
	}
}

// (4) Same-ID OSPF MD5 with different keys: strict rejects, lenient
// warns and keeps first key. Identical restatement still compiles.
func TestOSPFMD5DuplicateKeyConflict15935(t *testing.T) {
	tree := hierTree(t, `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication { md5 1 key alpha; md5 1 key beta; }
            }
        }
    }
}`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict accepted same-ID different-key MD5 duplicate")
	} else if !strings.Contains(err.Error(), "md5 1") {
		t.Fatalf("strict error must name md5 1, got: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "duplicate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn on duplicate key-id, warnings=%v", cfg.Warnings)
	}
	iface := cfg.Protocols.OSPF.Areas[0].Interfaces[0]
	if len(iface.AuthMD5Keys) != 1 || iface.AuthMD5Keys[0].Key.Reveal() != "alpha" {
		t.Fatalf("first key must win deterministically, got %+v", iface.AuthMD5Keys)
	}
	// Reversed order keeps the (new) first key.
	treeR := hierTree(t, `protocols {
    ospf {
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                authentication { md5 1 key beta; md5 1 key alpha; }
            }
        }
    }
}`)
	cfgR, _ := CompileConfigLenient(treeR)
	if got := cfgR.Protocols.OSPF.Areas[0].Interfaces[0].AuthMD5Keys[0].Key.Reveal(); got != "beta" {
		t.Fatalf("reversed first key = %q, want beta", got)
	}
	// Controls: identical restatement and distinct IDs compile strict.
	for name, body := range map[string]string{
		"same-key-restated": `authentication { md5 1 key alpha; md5 1 key alpha; }`,
		"distinct-ids":      `authentication { md5 1 key alpha; md5 2 key beta; }`,
		"keyless-then-key":  `authentication { md5 1; md5 1 key alpha; }`,
	} {
		tr := hierTree(t, `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { `+body+` } } } }`)
		if _, err := CompileConfig(tr); err != nil {
			t.Fatalf("%s must compile strict: %v", name, err)
		}
	}
}
