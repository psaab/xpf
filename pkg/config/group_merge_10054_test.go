package config

import (
	"testing"
)

// #10054 — a `<*>` template inherited through another group must fan out at
// the destination like a direct one. The nested group's body is merged into
// the outer group's cloned body first (#4474 pre-expansion), and that inner
// merge wholesale-adopts into an empty clone — where pruneWildcardInstances9802
// drops the wildcard-keyed node as matching nothing by construction. The
// wildcard is consumed before the outer merge ever sees it.
//
// Fixture is the issue's measured case (base 68a4ec6fd).
func TestNestedWildcardFanout10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
  G { apply-groups H; }
}
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`
	cfg := compile9422(t, parseTree9422(t, text))
	for _, name := range []string{"ge-0/0/0", "ge-0/0/1"} {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			t.Fatalf("fixture broken: no %s", name)
		}
		if ifc.Description != "FROM-H" {
			t.Fatalf("%s Description=%q, want FROM-H (nested <*> never fanned out)", name, ifc.Description)
		}
	}
}

// Direct-shape control: `apply-groups H` delivers the description today
// (TestApplyGroupsExceptIsPerDestination9422's shape). Must not move.
func TestNestedWildcardDirectControl10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
}
apply-groups H;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`
	cfg := compile9422(t, parseTree9422(t, text))
	for _, name := range []string{"ge-0/0/0", "ge-0/0/1"} {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil || ifc.Description != "FROM-H" {
			t.Fatalf("direct wildcard fan-out moved: %s=%+v", name, ifc)
		}
	}
}

// Genuinely-unmatched control: with no destination the nested wildcard still
// prunes (#9802) — deferred matching must not invent a `<*>` instance.
func TestNestedWildcardUnmatchedStillPrunes10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
  G { apply-groups H; }
}
apply-groups G;
system { host-name p; }`
	tree := parseTree9422(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if n == nil {
				continue
			}
			for _, k := range n.Keys {
				if k == "<*>" {
					t.Fatalf("unmatched nested wildcard landed as a literal instance: %q", n.Keys)
				}
			}
			walk(n.Children)
		}
	}
	walk(tree.Children)
	if got := len(compile9422(t, parseTree9422(t, text)).Interfaces.Interfaces); got != 0 {
		t.Fatalf("compiled %d interfaces, want 0", got)
	}
}

// Nested under a container: the `apply-groups H` sits inside G's own
// `interfaces` block, so the inner merge adopts the bare wildcard node
// itself (not just its parent). It must survive to fan out at the real
// destination too.
func TestNestedWildcardUnderContainer10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
  G { interfaces { apply-groups H; } }
}
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`
	cfg := compile9422(t, parseTree9422(t, text))
	for _, name := range []string{"ge-0/0/0", "ge-0/0/1"} {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil || ifc.Description != "FROM-H" {
			t.Fatalf("%s Description=%q, want FROM-H", name, ifc.Description)
		}
	}
}

// Memo-cache order: G's inner expansion caches H's body before H's own direct
// application runs. The cached body must carry the wildcard intact, so the
// direct application fans out exactly as if it ran first.
func TestNestedWildcardMemoOrder10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
  G { apply-groups H; }
}
apply-groups [ G H ];
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	ifc := compile9422(t, parseTree9422(t, text)).Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Description != "FROM-H" {
		t.Fatalf("ge-0/0/0 Description=%q, want FROM-H", ifc.Description)
	}
}

// Per-destination exclusion through nesting, with the wildcard template
// TestApplyGroupsExceptNestedPerDestination9862 could not use: only ge-0/0/1
// excludes H, so the description lands on ge-0/0/0 alone.
func TestNestedWildcardPerDestinationExcept10054(t *testing.T) {
	const text = `groups {
  H { interfaces { <*> { description FROM-H; } } }
  G { apply-groups H; }
}
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0/0/1 { apply-groups-except H; unit 0 { family inet { address 10.0.1.1/24; } } }
}`
	cfg := compile9422(t, parseTree9422(t, text))
	applied := cfg.Interfaces.Interfaces["ge-0/0/0"]
	excluded := cfg.Interfaces.Interfaces["ge-0/0/1"]
	if applied == nil || excluded == nil {
		t.Fatalf("fixture broken: interfaces = %d", len(cfg.Interfaces.Interfaces))
	}
	if applied.Description != "FROM-H" {
		t.Fatalf("ge-0/0/0 Description=%q, want FROM-H", applied.Description)
	}
	if excluded.Description != "" {
		t.Fatalf("ge-0/0/1 inherited nested H despite its exclusion: Description=%q", excluded.Description)
	}
}

// A nested wildcard can itself carry another nested wildcard template. An
// exclusion in the outer group must remove only the excluded contributor
// before the wildcard is deferred outward; H's own member must survive.
func TestNestedWildcardInnerExceptStaysFiltered10054(t *testing.T) {
	const text = `groups {
  J { interfaces { <*> { description FROM-J; } } }
  H { interfaces { <*> { mtu 9000; apply-groups J; } } }
  G { interfaces { apply-groups-except J; } apply-groups H; }
}
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	ifc := compile9422(t, parseTree9422(t, text)).Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("fixture broken: ge-0/0/0 missing")
	}
	if ifc.MTU != 9000 {
		t.Fatalf("ge-0/0/0 MTU=%d, want 9000 from H", ifc.MTU)
	}
	if ifc.Description != "" {
		t.Fatalf("ge-0/0/0 Description=%q, want empty because J is excluded", ifc.Description)
	}
}
