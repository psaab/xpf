package config

import "testing"

// #9125: an explicit `preference 5` was silently dropped because 5 is also the
// compiler's own default, and the merge of two hierarchical `route <p> { }`
// blocks tested `route.Preference != 5` to decide whether the later block had
// said anything.
//
//	route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
//	route 10.0.0.0/8 { preference 5; }        -> compiled Preference = 10
//
// while `preference 7` in the same position compiled to 7. The operator's
// statement was accepted at the STRICT commit gate and ignored.
//
// NextHopEntry already carried HasPreference and HasMetric for exactly this
// reason. The pattern was in the same package, one type over, which is why the
// omission was invisible: a reader checking "does this codebase know about
// sentinel collisions" finds that it does.
func TestStaticRoutePreferenceSentinel9125(t *testing.T) {
	for _, tc := range []struct {
		name         string
		text         string
		wantRef      int
		wantHas      bool
		wantNextHops int
	}{
		// THE DEFECT. 5 is the value that collides with the sentinel.
		{"later block sets preference 5", `routing-options { static {
			route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
			route 10.0.0.0/8 { preference 5; } } }`, 5, true, 1},

		// CONTROL: any other value already worked. Without this row a fix that
		// simply always applied the later block would look identical.
		{"later block sets preference 7", `routing-options { static {
			route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
			route 10.0.0.0/8 { preference 7; } } }`, 7, true, 1},

		// CONTROL: a later block that says NOTHING about preference must not
		// clobber the earlier one. This is the case the `!= 5` test was
		// actually trying to protect, and it must keep working.
		{"later block is silent on preference", `routing-options { static {
			route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
			route 10.0.0.0/8 { next-hop 192.0.2.2; } } }`, 10, true, 2},

		// The bit itself: explicit 5 and absent 5 are now distinguishable,
		// which is the property the whole fix rests on.
		{"single block, explicit 5", `routing-options { static {
			route 10.0.0.0/8 { next-hop 192.0.2.1; preference 5; } } }`, 5, true, 1},
		{"single block, no preference", `routing-options { static {
			route 10.0.0.0/8 { next-hop 192.0.2.1; } } }`, 5, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			c, err := CompileConfig(&ConfigTree{Children: root.Children})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(c.RoutingOptions.StaticRoutes) != 1 {
				t.Fatalf("want exactly one merged route, got %d", len(c.RoutingOptions.StaticRoutes))
			}
			r := c.RoutingOptions.StaticRoutes[0]
			if r.Preference != tc.wantRef {
				t.Errorf("Preference = %d, want %d", r.Preference, tc.wantRef)
			}
			if r.HasPreference != tc.wantHas {
				t.Errorf("HasPreference = %v, want %v — an explicit preference and an absent "+
					"one must be distinguishable, which is the whole point of the bit",
					r.HasPreference, tc.wantHas)
			}
			if len(r.NextHops) != tc.wantNextHops {
				t.Fatalf("NextHops = %d, want %d: %+v", len(r.NextHops), tc.wantNextHops, r.NextHops)
			}
			for _, hop := range r.NextHops {
				if hop.HasPreference {
					t.Fatalf("same-spelling next-hop was independently stamped: %+v", hop)
				}
			}
			tiers := StaticRouteNextHopTiers(r)
			if len(tiers) != 1 || tiers[0].Preference != tc.wantRef ||
				len(tiers[0].NextHops) != tc.wantNextHops {
				t.Fatalf("effective next-hop tiers = %+v, want one tier at preference %d with %d paths",
					tiers, tc.wantRef, tc.wantNextHops)
			}
		})
	}
}

// TestStaticRoutePreferenceFlatSet9125 pins the flat-set spelling too. The
// braced and flat-set paths set the field at DIFFERENT sites in
// compiler_routing.go, and only one of them originally got the bit when this
// fix was first written — the other was found by re-reading the diff, not by a
// test.
func TestStaticRoutePreferenceFlatSet9125(t *testing.T) {
	tr := &ConfigTree{}
	for _, l := range []string{
		"set routing-options static route 10.0.0.0/8 next-hop 192.0.2.1",
		"set routing-options static route 10.0.0.0/8 preference 5",
	} {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	c, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("want one route, got %d", len(c.RoutingOptions.StaticRoutes))
	}
	if r := c.RoutingOptions.StaticRoutes[0]; !r.HasPreference || r.Preference != 5 {
		t.Errorf("flat-set explicit `preference 5`: Preference=%d HasPreference=%v, want 5/true",
			r.Preference, r.HasPreference)
	}
}
