package config

import (
	"strings"
	"testing"
)

func fwTree9876(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// TestValuelessFirewallFromBracedFamilyRejects9876 is the #9876 gate.
//
// The #8480 gate took `fam.Children` as the filter level, so the braced-nested
// `family { inet { filter ... } }` shape — which compileFirewall descends —
// presented an AF node where the gate required a `filter` node and was SKIPPED.
// The two args-0 prefix-list leaves (`schema_cos.go`) also escape the generic
// #8597 belt (`missingArgs > 0`), so a valueless prefix-list in this shape
// committed strict-clean as match-ANY: `then discard` over-drops, `then accept`
// opens, on that criterion.
func TestValuelessFirewallFromBracedFamilyRejects9876(t *testing.T) {
	rows := []struct {
		name string
		from string
		then string
		leaf string
	}{
		{"braced source-prefix-list discard", `source-prefix-list;`, `discard`, "source-prefix-list"},
		{"braced source-prefix-list accept", `source-prefix-list;`, `accept`, "source-prefix-list"},
		{"braced destination-prefix-list discard", `destination-prefix-list;`, `discard`, "destination-prefix-list"},
		{"braced destination-prefix-list accept", `destination-prefix-list;`, `accept`, "destination-prefix-list"},
		// The gate is leaf-blind within the value-bearing set: once it descends
		// the braced shape it must cover the argument-declaring leaves too
		// (the #8597 belt also rejects these on the CheckText path, but the
		// strict-compile path reaches this gate first).
		{"braced protocol discard", `protocol;`, `discard`, "protocol"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			src := `firewall { family { inet { filter F { term T { from { ` + row.from +
				` } then { ` + row.then + `; } } } } } }`
			_, err := CompileConfig(fwTree9876(t, src))
			if err == nil {
				t.Fatalf("a braced-nested valueless `from %s` was accepted — the term "+
					"matches EVERY packet on that criterion", row.from)
			}
			if !strings.Contains(err.Error(), row.leaf) {
				t.Fatalf("rejected for the wrong reason\n  want substring: %q\n  got: %v",
					row.leaf, err)
			}
			if !strings.Contains(err.Error(), "8480") {
				t.Fatalf("rejected, but not by the #8480 gate\n  got: %v", err)
			}
			if !strings.Contains(err.Error(), "family inet") {
				t.Fatalf("rejected, but the diagnostic does not name the address family\n  got: %v", err)
			}
		})
	}
}

// TestValuelessFirewallFromFlatStillRejects9876 regression-pins the spellings
// the #8480 gate already covered, including the F-104 diagnostic: the flat-shape
// reject used to read `firewall family family filter ...` because it printed
// `fam.Name()` (Keys[0]) instead of the AF token.
func TestValuelessFirewallFromFlatStillRejects9876(t *testing.T) {
	t.Run("flat family inet names the family", func(t *testing.T) {
		src := `firewall { family inet { filter F { term T { from { source-prefix-list; } then { discard; } } } } }`
		_, err := CompileConfig(fwTree9876(t, src))
		if err == nil {
			t.Fatal("flat valueless `from source-prefix-list;` was accepted")
		}
		for _, want := range []string{"source-prefix-list", "8480", `family inet filter "F" term "T"`} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("want substring %q\n  got: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "family family") {
			t.Fatalf("F-104 diagnostic regressed: %v", err)
		}
	})
	t.Run("family-less still rejects without a family token", func(t *testing.T) {
		src := `firewall { filter F { term T { from { source-prefix-list; } then { discard; } } } }`
		_, err := CompileConfig(fwTree9876(t, src))
		if err == nil {
			t.Fatal("family-less valueless `from source-prefix-list;` was accepted")
		}
		for _, want := range []string{"source-prefix-list", "8480", `firewall filter "F" term "T"`} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("want substring %q\n  got: %v", want, err)
			}
		}
	})
}

// TestValuelessFirewallFromBlockNamesReject9876 pins the hierarchical block-name
// shapes the compiler resolves via namedInstances (`filter { F { ... } }`,
// `term { T { ... } }`). The gate read `filt.Children`/`Keys[1]` directly, so
// both compiled match-ANY while the gate walked past them.
func TestValuelessFirewallFromBlockNamesReject9876(t *testing.T) {
	rows := []struct {
		name string
		src  string
	}{
		{"filter block-name", `firewall { family inet { filter { F { term T { from { source-prefix-list; } then { discard; } } } } } }`},
		{"term block-name", `firewall { family inet { filter F { term { T { from { source-prefix-list; } then { discard; } } } } } }`},
		{"braced family with block names", `firewall { family { inet { filter { F { term { T { from { destination-prefix-list; } then { accept; } } } } } } } }`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, err := CompileConfig(fwTree9876(t, row.src))
			if err == nil {
				t.Fatalf("%s: valueless prefix-list was accepted", row.name)
			}
			if !strings.Contains(err.Error(), "prefix-list") || !strings.Contains(err.Error(), "8480") {
				t.Fatalf("%s: rejected for the wrong reason: %v", row.name, err)
			}
		})
	}
}

// TestValuelessFirewallFromBracedValuedCommits9876 is the over-reach guard: the
// widened walk must not flag leaves that carry values, presence-only flags, or
// empty `from` blocks in the braced shape.
func TestValuelessFirewallFromBracedValuedCommits9876(t *testing.T) {
	braced := func(fromBody string) string {
		return `firewall { family { inet { filter F { term T { from { ` + fromBody +
			` } then { discard; } } } } } }`
	}
	t.Run("valued protocol commits", func(t *testing.T) {
		if _, err := CompileConfig(fwTree9876(t, braced(`protocol tcp;`))); err != nil {
			t.Fatalf("valued leaf must commit, got: %v", err)
		}
	})
	t.Run("is-fragment flag commits", func(t *testing.T) {
		if _, err := CompileConfig(fwTree9876(t, braced(`is-fragment;`))); err != nil {
			t.Fatalf("presence-only flag must commit, got: %v", err)
		}
	})
	t.Run("empty from commits", func(t *testing.T) {
		if _, err := CompileConfig(fwTree9876(t, braced(``))); err != nil {
			t.Fatalf("empty from must commit, got: %v", err)
		}
	})
	t.Run("valued prefix-list is not an 8480 reject", func(t *testing.T) {
		// PL1 is undefined, so strict still rejects — but through the
		// undefined-reference gate, proving this gate correctly read the leaf
		// as valued rather than flagging it.
		_, err := CompileConfig(fwTree9876(t, braced(`source-prefix-list PL1;`)))
		if err == nil {
			t.Fatal("undefined prefix-list reference must still reject")
		}
		if strings.Contains(err.Error(), "8480") {
			t.Fatalf("valued leaf was flagged valueless: %v", err)
		}
	})
}

// TestValuelessFirewallFromBracedLenientWarns9876 pins the #1960 no-brick side
// for the newly gated shape: a persisted braced-nested valueless term must boot
// with a warning on the tolerant path.
func TestValuelessFirewallFromBracedLenientWarns9876(t *testing.T) {
	src := `firewall { family { inet { filter F { term T { from { source-prefix-list; } then { discard; } } } } } }`
	if _, err := CompileConfig(fwTree9876(t, src)); err == nil {
		t.Fatal("control failed: the strict path must reject this")
	}
	cfg, err := CompileConfigLenient(fwTree9876(t, src))
	if err != nil {
		t.Fatalf("the tolerant path must not brick the node: %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-prefix-list") && strings.Contains(w, "8480") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tolerant path must WARN, not swallow; warnings: %v", cfg.Warnings)
	}
}
