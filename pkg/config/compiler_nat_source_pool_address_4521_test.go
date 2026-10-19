// #4521: a source-NAT pool `address [ a b c ]` in flat-set / bracket-list
// form silently kept ONLY the first IP. `address` is UNMODELED under a source
// pool in the schema, so SetPath's unmodeled-leaf path collapses every trailing
// token onto ONE node (Keys=["address","a","b","c"]); the compiler read only
// prop.Keys[1] (and the range branch required Keys[2]=="to"), so a discrete
// bracket list with no `to` truncated to the first address → the SNAT pool
// shrank to one IP → premature source-port exhaustion (#2419-class silent
// truncation).
//
// The fix reads the WHOLE Keys[1:] token stream (plus the block children) via
// appendPoolAddresses, expanding any `<low> to <high>` sub-range in place.
// RED-on-revert:
//   - bracket list `[ a b c ]` compiles 3 addresses [RED: only 1].
//   - discrete `set` lines still compile 3/3.
//   - a range `a to b` still expands correctly.
//   - the hierarchical block `address { a; b; c }` shape is unaffected.
//
// Flat-set syntax is built via ParseSetCommand/SetPath (snatPoolTree), never
// NewParser; the hierarchical block fixture uses NewParser (the correct tool
// for block shapes).
package config

import "testing"

func assertPoolAddrs4521(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("pool addresses = %v (len %d), want %v (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pool address[%d] = %q, want %q (full got=%v)", i, got[i], want[i], got)
		}
	}
}

// TestSourceNATPoolAddressBracketList_4521 is the core RED-on-revert: a
// bracket list must compile ALL three addresses. On revert (read only
// prop.Keys[1]) the pool keeps only the first IP.
func TestSourceNATPoolAddressBracketList_4521(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address [ 203.0.113.1/32 203.0.113.2/32 203.0.113.3/32 ]")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	assertPoolAddrs4521(t, pool.Addresses,
		[]string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"})
}

// TestSourceNATPoolAddressDiscreteLines_4521: three discrete `set` lines still
// yield 3/3 (the discrete form was already correct; guards against a
// regression from the multi-value read).
func TestSourceNATPoolAddressDiscreteLines_4521(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.1/32",
		"set security nat source pool p1 address 203.0.113.2/32",
		"set security nat source pool p1 address 203.0.113.3/32")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	assertPoolAddrs4521(t, pool.Addresses,
		[]string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"})
}

// TestSourceNATPoolAddressRange_4521: an `a to b` range still expands to every
// IP in the (inclusive) span.
func TestSourceNATPoolAddressRange_4521(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 203.0.113.1/32 to 203.0.113.3/32")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	assertPoolAddrs4521(t, pool.Addresses,
		[]string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"})
}

// TestSourceNATPoolAddressBracketMixedRange_4521: a bracket list may mix
// discrete addresses and a `<low> to <high>` sub-range. `[ .1 .5 to .7 ]` →
// .1 plus the .5-.7 span.
func TestSourceNATPoolAddressBracketMixedRange_4521(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address [ 203.0.113.1/32 203.0.113.5/32 to 203.0.113.7/32 ]")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	assertPoolAddrs4521(t, pool.Addresses,
		[]string{"203.0.113.1/32", "203.0.113.5/32", "203.0.113.6/32", "203.0.113.7/32"})
}

// TestSourceNATPoolAddressHierarchicalBlock_4521: the `address { a; b; c }`
// block shape (parsed via NewParser — the correct tool for block shapes)
// compiles every child address. This exercises the prop.Children path.
func TestSourceNATPoolAddressHierarchicalBlock_4521(t *testing.T) {
	const cfgText = `
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        source {
            pool p1 {
                address {
                    203.0.113.1/32;
                    203.0.113.2/32;
                    203.0.113.3/32;
                }
            }
            rule-set RS {
                from zone trust;
                to zone untrust;
                rule R1 {
                    match {
                        source-address 10.0.0.0/24;
                    }
                    then {
                        source-nat {
                            pool p1;
                        }
                    }
                }
            }
        }
    }
}
`
	tree, errs := NewParser(cfgText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 missing")
	}
	assertPoolAddrs4521(t, pool.Addresses,
		[]string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"})
}
