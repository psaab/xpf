package config

import (
	"strings"
	"testing"
)

// #15696: protocols router-advertisement interface <if> prefix <cidr> —
// SetPath leaf-then-container split and compileRouterAdvertisement's
// lack of prefix find-or-create emitted duplicate conflicting PIOs on
// the wire (pkg/ra sender emits one PIO per RAPrefix entry).

func raPrefixes15696(t *testing.T, tree *ConfigTree, iface string) []*RAPrefix {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile lenient: %v", err)
	}
	for _, ra := range cfg.Protocols.RouterAdvertisement {
		if ra != nil && ra.Interface == iface {
			return ra.Prefixes
		}
	}
	t.Fatalf("no RA interface %q in %+v", iface, cfg.Protocols.RouterAdvertisement)
	return nil
}

func assertOneMergedPrefix15696(t *testing.T, pfxs []*RAPrefix, want RAPrefix) {
	t.Helper()
	if len(pfxs) != 1 {
		t.Fatalf("Prefixes = %d entries %+v, want exactly 1 merged entry", len(pfxs), pfxs)
	}
	got := pfxs[0]
	if got == nil {
		t.Fatal("merged prefix is nil")
	}
	if got.Prefix != want.Prefix || got.OnLink != want.OnLink || got.Autonomous != want.Autonomous ||
		got.ValidLifetime != want.ValidLifetime || got.PreferredLife != want.PreferredLife ||
		got.PreferredLifeSet != want.PreferredLifeSet {
		t.Fatalf("merged prefix = %+v, want %+v", *got, want)
	}
}

// Hier dup: two prefix blocks for the same CIDR in one interface block
// must merge into one RAPrefix carrying both settings (no duplicate PIO).
func TestRAPrefixDupHierSameBlock15696(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 { valid-lifetime 100; preferred-lifetime 50; }
            prefix 2001:db8::/64 { no-autonomous; }
        }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false,
		ValidLifetime: 100, PreferredLife: 50, PreferredLifeSet: true,
	})
	// Strict must also commit clean with the merged shape.
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict compile: %v", err)
	}
}

// Sibling interface blocks naming the same interface (find-or-create already
// merges the interface) must also merge the same prefix inside.
func TestRAPrefixDupSiblingInterfaceBlocks15696(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 { prefix 2001:db8::/64 { valid-lifetime 100; } }
        interface ge-0/0/0.0 { prefix 2001:db8::/64 { no-autonomous; no-onlink; } }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: false, Autonomous: false, ValidLifetime: 100,
	})
}

// Flat leaf-then-container: bare `set ... prefix P` then
// `set ... prefix P no-autonomous` must produce ONE tree node (FormatSet
// shows one prefix statement carrying the flag) and ONE merged RAPrefix —
// not a bare leaf twin plus a container twin.
func TestRAPrefixDupFlatLeafThenContainer15696(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64",
		"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous",
	)
	out := tree.FormatSet()
	if n := strings.Count(out, "prefix 2001:db8::/64"); n != 1 {
		t.Fatalf("FormatSet has %d prefix statements, want 1 merged:\n%s", n, out)
	}
	if !strings.Contains(out, "prefix 2001:db8::/64 no-autonomous") {
		t.Fatalf("FormatSet lost no-autonomous:\n%s", out)
	}
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false,
	})
}

// Flat: valid-lifetime in one set, flag in another — compiler-level merge
// must keep both on the single entry.
func TestRAPrefixDupFlatLifetimeThenFlag15696(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 valid-lifetime 100",
		"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous",
		"set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 preferred-lifetime 0",
	)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false,
		ValidLifetime: 100, PreferredLife: 0, PreferredLifeSet: true,
	})
}

// Distinct prefixes must stay distinct (find-or-create is keyed by CIDR).
func TestRAPrefixDistinctPrefixesKept15696(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 { no-autonomous; }
            prefix 2001:db8:1::/64 { valid-lifetime 200; }
            prefix 2001:db8::/64 { valid-lifetime 100; }
        }
    }
}`)
	pfxs := raPrefixes15696(t, tree, "ge-0/0/0.0")
	if len(pfxs) != 2 {
		t.Fatalf("Prefixes = %d %+v, want 2 distinct", len(pfxs), pfxs)
	}
	byPfx := map[string]*RAPrefix{}
	for _, p := range pfxs {
		byPfx[p.Prefix] = p
	}
	if p := byPfx["2001:db8::/64"]; p == nil || p.Autonomous || p.ValidLifetime != 100 {
		t.Fatalf("2001:db8::/64 = %+v, want merged {Autonomous:false Valid:100}", p)
	}
	if p := byPfx["2001:db8:1::/64"]; p == nil || !p.Autonomous || p.ValidLifetime != 200 {
		t.Fatalf("2001:db8:1::/64 = %+v, want {Autonomous:true Valid:200}", p)
	}
}

// Later explicit setting overrides earlier for the same field, matching
// scalar leaf semantics inside the merged entry.
func TestRAPrefixDupLaterLifetimeOverrides15696(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64 { valid-lifetime 100; }
            prefix 2001:db8::/64 { valid-lifetime 300; preferred-lifetime 60; }
        }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: true,
		ValidLifetime: 300, PreferredLife: 60, PreferredLifeSet: true,
	})
}

// Applied (groups-expanded / leaf-then-container) shapes: a bare prefix
// leaf followed by a container for the same CIDR in hierarchical text
// must not twin.
func TestRAPrefixDupHierLeafThenContainer15696(t *testing.T) {
	tree := hierTree(t, `protocols {
    router-advertisement {
        interface ge-0/0/0.0 {
            prefix 2001:db8::/64;
            prefix 2001:db8::/64 { no-autonomous; valid-lifetime 100; }
        }
    }
}`)
	assertOneMergedPrefix15696(t, raPrefixes15696(t, tree, "ge-0/0/0.0"), RAPrefix{
		Prefix: "2001:db8::/64", OnLink: true, Autonomous: false, ValidLifetime: 100,
	})
}

// The AST promotion must NOT collapse other meaningful leaf+container
// twins: policy `then permit` + `then permit application-services` keeps
// its two-node split (already pinned by #15682, re-asserted here for the
// generalized condition so a widening regression fails in this file too).
func TestRAPrefixPromotionKeepsThenPermitSplit15696(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then permit application-services utm",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", cmd, err)
		}
	}
	if n := thenActionNodeCount(tree, "permit"); n != 2 {
		t.Fatalf("then permit nodes = %d, want 2 (two-node split preserved)", n)
	}
}
