// #13212 (D3-06): #8436 made split `pool P { ... }` blocks share one
// NATPool, but compileNATSource kept per-block post-processing inside the
// merge loop:
//
//   - the 1024-65535 default was stamped at the end of EACH pool block, so
//     `pool p1 { address ... }` followed by `pool p1 { port { no-translation; } }`
//     left PortNoTranslation=true alongside the invented 1024-65535 range;
//   - setPortRange never cleared PortRangeInvalidSpec on a later valid
//     range, and never cleared PortLow/PortHigh on a later invalid range, so
//     the strict gate hard-rejected a pool the operator had corrected;
//   - the deterministic-NAT validation ran inside compileNATSource (once
//     per `security nat source` block) over SourcePools in Go map order, so
//     a deterministic pool split across sibling `source {}` blocks was
//     rejected before its second half was merged, and multi-pool errors
//     named a random pool per run.
//
// The fix defers defaulting + deterministic validation to compileNAT (after
// every `source` block is merged), iterates pools in sorted name order, and
// makes setPortRange / no-translation override each other (later leaf wins).
//
// Hierarchical fixtures MUST use NewParser; flat-set `set` lines MUST be
// built via ParseSetCommand/SetPath (snatPoolTree), never NewParser.
package config

import (
	"strings"
	"testing"
)

// Split across two pool blocks: address first, no-translation second. The
// merged pool must carry no invented port range. RED on master: block 1
// stamps 1024-65535, block 2 only sets PortNoTranslation.
func TestNATSourcePoolSplitNoTranslationAfterAddress13212(t *testing.T) {
	const cfgText = `
security {
    nat {
        source {
            pool p1 {
                address {
                    198.51.100.1/32;
                }
            }
            pool p1 {
                port {
                    no-translation;
                }
            }
        }
    }
}
`
	tree, perrs := NewParser(cfgText).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("pool p1 missing")
	}
	if !pool.PortNoTranslation {
		t.Fatalf("PortNoTranslation = false, want true (second block's no-translation lost)")
	}
	if pool.PortLow != 0 || pool.PortHigh != 0 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 0/0: no-translation pools carry no "+
			"port range (#7173); the per-block default stamped 1024-65535 before the "+
			"no-translation block merged (#13212)", pool.PortLow, pool.PortHigh)
	}
}

// Reverse order: no-translation first, explicit range second. The later
// range wins and must clear the no-translation flag. RED on master:
// PortNoTranslation stays true alongside the 2000-3000 range.
func TestNATSourcePoolSplitRangeAfterNoTranslation13212(t *testing.T) {
	const cfgText = `
security {
    nat {
        source {
            pool p1 {
                address {
                    198.51.100.1/32;
                }
                port {
                    no-translation;
                }
            }
            pool p1 {
                port {
                    range 2000 to 3000;
                }
            }
        }
    }
}
`
	tree, perrs := NewParser(cfgText).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("pool p1 missing")
	}
	if pool.PortNoTranslation {
		t.Fatalf("PortNoTranslation = true alongside range %d-%d, want false: "+
			"the later explicit range overrides no-translation (#13212)",
			pool.PortLow, pool.PortHigh)
	}
	if pool.PortLow != 2000 || pool.PortHigh != 3000 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 2000/3000", pool.PortLow, pool.PortHigh)
	}
}

// Invalid range then valid override: the later valid range must clear the
// recorded invalid spec, so the strict gate does not reject a corrected
// pool. RED on master: PortRangeInvalidSpec stays set and CompileConfig
// hard-rejects.
func TestNATSourcePoolInvalidThenValidRangeClearsSpec13212(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source pool p1 port range 5000 to 100",
		"set security nat source pool p1 port range 2000 to 3000")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile rejected a pool whose later valid range overrides the "+
			"earlier invalid one: %v (stale PortRangeInvalidSpec, #13212)", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("pool p1 missing")
	}
	if pool.PortRangeInvalidSpec != "" {
		t.Fatalf("PortRangeInvalidSpec = %q, want cleared by the later valid range", pool.PortRangeInvalidSpec)
	}
	if pool.PortLow != 2000 || pool.PortHigh != 3000 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want 2000/3000", pool.PortLow, pool.PortHigh)
	}
}

// Valid range then invalid override: the later invalid range must be the
// recorded verdict (strict reject) and must not leave the old valid range
// stamped for the lenient path to translate through.
func TestNATSourcePoolValidThenInvalidRangeClearsRange13212(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source pool p1 port range 2000 to 3000",
		"set security nat source pool p1 port range 5000 to 100")
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("compile accepted a pool whose last port range is reversed; " +
			"want strict reject via PortRangeInvalidSpec (#13212)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil {
		t.Fatal("pool p1 missing")
	}
	if pool.PortRangeInvalidSpec != "5000 to 100" {
		t.Fatalf("PortRangeInvalidSpec = %q, want %q", pool.PortRangeInvalidSpec, "5000 to 100")
	}
	if pool.PortLow != 1024 || pool.PortHigh != 65535 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want safe default 1024/65535 after "+
			"discarding the earlier valid range; PortRangeInvalidSpec keeps the "+
			"pool unusable on the lenient path (#13212)", pool.PortLow, pool.PortHigh)
	}
}

// Deterministic pool split across two sibling `source {}` blocks: the
// address + block-size land in block 1, the host address in block 2. The
// merged pool is complete, so compile must succeed. RED on master:
// compileNATSource validates after block 1 and rejects with
// "deterministic host address required".
func TestNATSourceDeterministicSplitAcrossSourceBlocks13212(t *testing.T) {
	const cfgText = `
security {
    nat {
        source {
            pool CG {
                address 203.0.113.0/24;
                port {
                    deterministic {
                        block-size 1024;
                    }
                }
            }
        }
        source {
            pool CG {
                port {
                    deterministic {
                        host address 100.64.0.0/20;
                    }
                }
            }
        }
    }
}
`
	tree, perrs := NewParser(cfgText).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("deterministic pool split across sibling source blocks rejected "+
			"before the second block merged: %v (#13212)", err)
	}
	pool := cfg.Security.NAT.SourcePools["CG"]
	if pool == nil || pool.Deterministic == nil {
		t.Fatalf("pool CG / deterministic config missing: %+v", pool)
	}
	if pool.Deterministic.BlockSize != 1024 || pool.Deterministic.HostAddress != "100.64.0.0/20" {
		t.Fatalf("deterministic = %+v, want block-size 1024 host 100.64.0.0/20", pool.Deterministic)
	}
}

// Two invalid deterministic pools: the error must name the lexicographically
// first pool on every run (sorted iteration), not a random one from Go map
// order. RED on master in most runs.
func TestNATSourceDeterministicValidationSortedOrder13212(t *testing.T) {
	for range 20 {
		tree := snatPoolTree(t,
			"set security nat source pool zz address 198.51.100.1/32",
			"set security nat source pool zz port deterministic block-size 1024",
			"set security nat source pool aa address 198.51.100.2/32",
			"set security nat source pool aa port deterministic block-size 1024")
		// snatPoolTree references pool p1 in its rule; the pools under test
		// are aa/zz. Compile error comes from deterministic validation,
		// which runs before the rule-set/reference gates that would
		// otherwise fire first on the strict path.
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected deterministic validation error")
		}
		if !strings.Contains(err.Error(), `pool "aa"`) {
			t.Fatalf("error = %v, want it to name pool \"aa\" first "+
				"(sorted pool order, #13212)", err)
		}
	}
}

// Control: a plain no-port pool still gets the 1024-65535 default stamped
// exactly once (existing behavior pinned by #6812 contract tests).
func TestNATSourcePoolDefaultRangeUnaffected13212(t *testing.T) {
	tree := snatPoolTree(t,
		"set security nat source pool p1 address 198.51.100.1/32")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool.PortLow != 1024 || pool.PortHigh != 65535 {
		t.Fatalf("PortLow/PortHigh = %d/%d, want default 1024/65535", pool.PortLow, pool.PortHigh)
	}
}
