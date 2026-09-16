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
	t.Run("family-less still rejects, attributed to the implicit inet scope", func(t *testing.T) {
		// #9899 re-homes Junos' [edit firewall filter] spelling under a
		// synthetic `family inet` scope before validation, so the gate sees
		// the same compiler view as the explicit spelling and the
		// diagnostic names family inet. The reject itself is unchanged.
		src := `firewall { filter F { term T { from { source-prefix-list; } then { discard; } } } }`
		_, err := CompileConfig(fwTree9876(t, src))
		if err == nil {
			t.Fatal("family-less valueless `from source-prefix-list;` was accepted")
		}
		for _, want := range []string{"source-prefix-list", "8480", `family inet filter "F" term "T"`} {
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

// TestValuelessFirewallFromSkipsQuarantinedMembers9876 pins the #9883
// integration of the gate: members the compiler quarantines (an undeclared
// family token, or a structured member carrying residue) compile to NOTHING,
// so there are no compiled terms to check and the gate must skip them —
// exactly like the compiler skips them. Without the skip the gate warns
// #8480 for a term that enforces no rule at all.
//
// Strict cannot carry this cell: the #9017 token gate rejects unknown
// families earlier in the prewalk, so the lenient path proves it. One
// fixture in document order — quarantined filters first (a plain unknown
// token, then a malformed-residue member), declared-family valueless term
// last — proving the skip continues the walk instead of aborting it.
func TestValuelessFirewallFromSkipsQuarantinedMembers9876(t *testing.T) {
	const src = `firewall { family inett { filter Q { term TQ { from { source-prefix-list; } then { discard; } } } } family { inett inet { filter R { term TR { from { source-prefix-list; } then { discard; } } } } } family inet { filter F { term T { from { source-prefix-list; } then { discard; } } } } }`
	t.Run("strict rejects via the token gate", func(t *testing.T) {
		_, err := CompileConfig(fwTree9876(t, src))
		if err == nil {
			t.Fatal("control failed: strict must reject the unknown family")
		}
		if !strings.Contains(err.Error(), "9017") {
			t.Fatalf("strict must reject through #9017 (which is why this cell rides lenient), got: %v", err)
		}
	})
	lenient := func(t *testing.T) *Config {
		t.Helper()
		cfg, err := CompileConfigLenient(fwTree9876(t, src))
		if err != nil {
			t.Fatalf("the tolerant path must not brick the node: %v", err)
		}
		return cfg
	}
	t.Run("9017 warning remains", func(t *testing.T) {
		for _, w := range lenient(t).Warnings {
			if strings.Contains(w, "9017") && strings.Contains(w, "inett") {
				return
			}
		}
		t.Fatalf("the #9017 quarantine warning must remain; warnings: %v", lenient(t).Warnings)
	})
	t.Run("no 8480 warning names a quarantined term", func(t *testing.T) {
		for _, w := range lenient(t).Warnings {
			if !strings.Contains(w, "8480") {
				continue
			}
			for _, quarantined := range []string{`"Q"`, `"TQ"`, `"R"`, `"TR"`, "inett"} {
				if strings.Contains(w, quarantined) {
					t.Fatalf("gate checked a quarantined term: %v", w)
				}
			}
		}
	})
	t.Run("quarantined filters install into neither pool", func(t *testing.T) {
		cfg := lenient(t)
		for _, pool := range []map[string]*FirewallFilter{cfg.Firewall.FiltersInet, cfg.Firewall.FiltersInet6} {
			for _, name := range []string{"Q", "R"} {
				if _, ok := pool[name]; ok {
					t.Fatalf("quarantined filter %q must compile to NOTHING", name)
				}
			}
		}
		if cfg.Firewall.FiltersInet["F"] == nil {
			t.Fatal("control failed: the declared filter F must install, or the absences above prove nothing")
		}
	})
	t.Run("declared valueless term still warns 8480", func(t *testing.T) {
		for _, w := range lenient(t).Warnings {
			if strings.Contains(w, "8480") && strings.Contains(w, `filter "F" term "T"`) {
				return
			}
		}
		t.Fatalf("the skip must continue the walk, not abort it; warnings: %v", lenient(t).Warnings)
	})
}
