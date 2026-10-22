package config

import "testing"

// Tests for #4820: a hand-authored `load override` config can carry two
// literal `probe <name> { ... }` TOP-LEVEL sibling blocks under `services
// rpm` (e.g. from concatenated config snippets). Same root cause as #4818
// (security zones): the hierarchical parser keeps repeated same-name blocks
// as separate siblings — it does NOT merge — and `load override` splices
// that raw candidate straight into the compiler. Before #4820, compileRPM
// (pkg/config/compiler_services.go) allocated a fresh RPMProbe per instance
// and did an unconditional `rpmCfg.Probes[probe.Name] = probe`, so the
// SECOND probe instance silently REPLACED the first, discarding ALL of its
// tests. Junos merges repeated blocks; the compiler now find-or-creates the
// RPMProbe by name so `test` blocks from every sibling instance accumulate
// into the SAME probe's Tests map.
//
// SHAPE NOTE (per CLAUDE.md): a duplicate top-level probe block is only
// expressible via the hierarchical / NewParser (load-override) path.
// Flat-set ParseSetCommand + SetPath merges two lines with an identical
// key-path into one node, so it is structurally immune and is NOT the
// reproducer here — parseHierText is.

// TestRPMProbeDupBlock4820TestsMerge is the primary RED-on-revert guard: two
// `probe p1 { ... }` top-level instances, each declaring a different test.
// Reverting compileRPM to unconditionally allocate a fresh RPMProbe per
// instance makes the second instance replace the first, so test t1 is
// dropped — RED.
func TestRPMProbeDupBlock4820TestsMerge(t *testing.T) {
	tree := parseHierText(t, `
services {
    rpm {
        probe p1 {
            test t1 {
                target 1.1.1.1;
            }
        }
        probe p1 {
            test t2 {
                target 2.2.2.2;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	probe := cfg.Services.RPM.Probes["p1"]
	if probe == nil {
		t.Fatalf("probe p1 missing")
	}
	if len(probe.Tests) != 2 {
		t.Fatalf("probe p1 tests = %d, want 2 (t1 dropped by block 2 overwrite — #4820): %+v", len(probe.Tests), probe.Tests)
	}
	t1 := probe.Tests["t1"]
	if t1 == nil || t1.Target != "1.1.1.1" {
		t.Fatalf("test t1 = %+v, want target 1.1.1.1 (#4820)", t1)
	}
	t2 := probe.Tests["t2"]
	if t2 == nil || t2.Target != "2.2.2.2" {
		t.Fatalf("test t2 = %+v, want target 2.2.2.2 (#4820)", t2)
	}
}

// TestRPMProbeDupBlock4820ThreeInstancesAllTestsSurvive covers three
// duplicate top-level probe instances (not just two), each contributing one
// test, to guard against an off-by-one find-or-create that only handles a
// pair.
func TestRPMProbeDupBlock4820ThreeInstancesAllTestsSurvive(t *testing.T) {
	tree := parseHierText(t, `
services {
    rpm {
        probe p1 {
            test t1 {
                target 1.1.1.1;
            }
        }
        probe p1 {
            test t2 {
                target 2.2.2.2;
            }
        }
        probe p1 {
            test t3 {
                target 3.3.3.3;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	probe := cfg.Services.RPM.Probes["p1"]
	if probe == nil {
		t.Fatalf("probe p1 missing")
	}
	for _, name := range []string{"t1", "t2", "t3"} {
		if probe.Tests[name] == nil {
			t.Fatalf("probe p1 missing test %q, tests = %+v (#4820)", name, probe.Tests)
		}
	}
}

// TestRPMProbeDupBlock4820SingleBlockUnchanged is the byte-identical
// negative control: a single probe instance with two tests must compile
// exactly as before the find-or-create change.
func TestRPMProbeDupBlock4820SingleBlockUnchanged(t *testing.T) {
	tree := parseHierText(t, `
services {
    rpm {
        probe p1 {
            test t1 {
                target 1.1.1.1;
            }
            test t2 {
                target 2.2.2.2;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	probe := cfg.Services.RPM.Probes["p1"]
	if probe == nil {
		t.Fatalf("probe p1 missing")
	}
	if len(probe.Tests) != 2 {
		t.Fatalf("probe p1 tests = %d, want 2", len(probe.Tests))
	}
}
