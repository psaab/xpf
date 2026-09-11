package config

import "testing"

// TestPackedRoutingInstanceSurvives8787 asserts the ABSOLUTE outcome of each
// spelling: the instance exists and carries the type the operator wrote.
//
// #8787: the brace-elided spelling dropped the ENTIRE routing instance, not one
// property. `routing-instances { ri1 instance-type forwarding; }` compiled to
// ZERO instances on a commit that reported success, because compileRoutingInstances
// skipped any child that was a leaf — and an elided instance is a leaf.
//
// THE HARMFUL DIRECTION IS `forwarding`. InstanceType == "forwarding" is what
// makes the daemon SKIP VRF creation (daemon_apply_interfaces.go), so a dropped
// value creates a VRF the operator asked NOT to have and moves interfaces into
// it — a forwarding/isolation change, not a lost label. Reachable from a loaded
// or peer-synced config FILE, not from flat `set`, so the boot and HA-sync
// paths rather than the CLI.
//
// WHY NOT "packed == braced". Both spellings producing ZERO instances agree
// perfectly, so an equality cell is green on exactly the defect it would exist
// to catch. Each spelling is asserted to produce the instance AND the type.
// (Constraint: team-lead. Same shape as the #8778 allowlist guard, where two
// allow-all spellings also agreed.)
func TestPackedRoutingInstanceSurvives8787(t *testing.T) {
	check := func(t *testing.T, label, text, wantType string, wantIfaces int) {
		t.Helper()
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", label, perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("%s: strict compile: %v", label, err)
		}
		if len(cfg.RoutingInstances) == 0 {
			t.Errorf("%s: ZERO routing instances compiled. The operator wrote one and the "+
				"commit succeeded. If wantType is `forwarding` this also creates a VRF "+
				"they asked not to have, because the daemon skips VRF creation only for "+
				"InstanceType==\"forwarding\" (#8787)", label)
			return
		}
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType != wantType {
				t.Errorf("%s: InstanceType=%q, want %q. A `forwarding` instance whose type "+
					"is lost becomes a VRF (#8787)", label, ri.InstanceType, wantType)
			}
			if len(ri.Interfaces) != wantIfaces {
				t.Errorf("%s: %d interface(s) bound, want %d. Interfaces missing from the "+
					"instance stay in the default table — a VRF isolation break (#3904)",
					label, len(ri.Interfaces), wantIfaces)
			}
		}
	}

	t.Run("packed forwarding", func(t *testing.T) {
		check(t, "packed forwarding",
			`routing-instances { ri1 instance-type forwarding; }`, "forwarding", 0)
	})
	t.Run("packed vrf with interface", func(t *testing.T) {
		check(t, "packed vrf with interface",
			`routing-instances { ri1 instance-type vrf interface ge-0/0/0.0; }`, "vrf", 1)
	})
	// CONTROL: the braced spelling always worked and must keep working. If the
	// fix broke it, the two assertions above would still pass.
	t.Run("control braced", func(t *testing.T) {
		check(t, "control braced",
			`routing-instances { ri1 { instance-type forwarding; } }`, "forwarding", 0)
	})
	// CONTROL: flat `set` builds a CHAIN rather than a Keys run and compiled
	// correctly before this fix; it must be unaffected by it.
	t.Run("control flat set", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, line := range []string{
			"set routing-instances ri1 instance-type forwarding",
			"set routing-instances ri1 interface ge-0/0/0.0",
		} {
			p, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := compileConfigWithOpts(tree, compileOpts{})
		if err != nil {
			t.Fatalf("flat set strict compile: %v", err)
		}
		if len(cfg.RoutingInstances) == 0 {
			t.Fatalf("flat set: ZERO instances — the CLI path regressed (#8787)")
		}
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType != "forwarding" || len(ri.Interfaces) != 1 {
				t.Errorf("flat set: type=%q ifaces=%d, want forwarding/1",
					ri.InstanceType, len(ri.Interfaces))
			}
		}
	})
	// A bare elided instance carries no properties and must not become a
	// phantom: it has no type, so it would compile as a VRF.
	t.Run("bare name is not an instance", func(t *testing.T) {
		tr, perrs := NewParser(`routing-instances { ri1; }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if len(cfg.RoutingInstances) != 0 {
			t.Errorf("a bare `ri1;` compiled to %d instance(s); it declares nothing and "+
				"would become an untyped VRF (#8787)", len(cfg.RoutingInstances))
		}
	})
}

// TestRoutingInstanceLeavesAreOffered8787 pins the SECOND, separable half of
// the #8787 change, because mutation showed it does not affect the first.
//
// When this cell was written, removing the schema declarations of
// `instance-type` and `interface` left every assertion in
// TestPackedRoutingInstanceSurvives8787 passing, because the compiler read the
// packed tail on its own. Since #9620 the normalizer splits a packed instance
// by these same declarations, so they now carry that cell too. This cell pins
// the other half: completion and `?` help offer the leaves. Without them the
// operator is offered 2 completions and neither is the one they need.
//
// Kept as its own cell so the two halves cannot be confused. #8785 is the
// reason: there, declaring a leaf was assumed to fix a drop and did not, and
// the only way to know which part did the work was to mutate each alone.
func TestRoutingInstanceLeavesAreOffered8787(t *testing.T) {
	comps := CompleteSetPathWithValues([]string{"routing-instances", "ri1", ""}, nil)
	got := map[string]bool{}
	for _, c := range comps {
		got[c.Name] = true
	}
	for _, want := range []string{"instance-type", "interface"} {
		if !got[want] {
			t.Errorf("completion after `set routing-instances <name> ` does not offer %q "+
				"(%d offered). The compiler reads it, so an operator is not told about a "+
				"leaf the config supports (#8787)", want, len(comps))
		}
	}
}
