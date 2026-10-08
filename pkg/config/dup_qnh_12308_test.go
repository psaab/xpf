package config

import (
	"strings"
	"testing"
)

// #12308: a repeated qualified-next-hop block for the SAME gateway compiles to
// TWO NextHopEntry halves — the interface on one, the preference on the other
// — where the flat-set spelling merges to ONE. The halves land in DIFFERENT
// failover tiers (the interface half inherits route preference 5, the
// preference half carries 250), so the author's single floating backup becomes
// a primary-tier path plus an interfaceless backup. Strict commit must refuse
// the re-opening and the tolerant path must warn; both must name the effect
// (split instances, not last-wins) so the remedy deletes nothing.
//
// FAIL-ON-REVERT: dropping the deepDupRules QNH rows lets the duplicate commit
// clean with zero warnings again.
func TestReopenedQualifiedNextHopIsRejectedAndReported12308(t *testing.T) {
	const dup = `routing-options { static { route 10.5.0.0/16 { qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; } qualified-next-hop 10.0.0.2 { preference 250; } } } }`
	const merged = `routing-options { static { route 10.5.0.0/16 { qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; preference 250; } } } }`

	// POSITIVE HALF: the merged spelling must carry both halves on ONE
	// next-hop, or the split asserted below is not attributable to the
	// re-opening.
	mc := compileText(t, merged)
	if mc == nil {
		t.Fatal("the merged control must compile")
	}
	if len(mc.RoutingOptions.StaticRoutes) != 1 || len(mc.RoutingOptions.StaticRoutes[0].NextHops) != 1 {
		t.Fatalf("the merged control must compile to one route with one next-hop, got %+v", mc.RoutingOptions.StaticRoutes)
	}
	mnh := mc.RoutingOptions.StaticRoutes[0].NextHops[0]
	if mnh.Interface == "" || !mnh.HasPreference {
		t.Fatalf("the merged control lost a half itself (iface=%q hasPref=%v); the fixture no longer isolates the re-opening",
			mnh.Interface, mnh.HasPreference)
	}

	tree, errs := NewParser(dup).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a re-opened qualified-next-hop still COMMITS CLEAN. It splits one floating " +
			"backup into two failover tiers, and a backup that installs at the wrong admin " +
			"distance is a failover that fires at the wrong time (#12308)")
	} else if !strings.Contains(err.Error(), "split") {
		t.Errorf("the strict rejection does not name the SPLIT effect, which is what was "+
			"measured in both authoring orders: %v", err)
	}
	t2, _ := NewParser(dup).Parse()
	cfg, err := CompileConfigLenient(t2)
	if err != nil || cfg == nil {
		t.Fatalf("the tolerant path must not hard-fail: %v", err)
	}
	found := ""
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "qualified-next-hop") {
			found = w
		}
	}
	if found == "" {
		t.Error("the tolerant path splits the backup into two tiers and reports nothing (#12308)")
	}
	// The message must state the measured outcome. The existing split-instances
	// vocabulary ("compiles independently ... neither sees the other's
	// settings") is exactly this defect: the interface half never sees the
	// preference half.
	if found != "" && !strings.Contains(found, "neither sees") {
		t.Errorf("the warning does not name the SPLIT effect, which is what was measured in "+
			"both authoring orders: %q", found)
	}
}

// OVER-REACH CONTROL. Two DIFFERENT gateways on one route are two legitimate
// floating backups — the walk keys on the gateway, so they must compile clean
// on both paths. Flat `set` lines for one gateway merge onto one node before
// the gate runs, so the canonical authoring shape is untouched too.
func TestDistinctQualifiedNextHopGatewaysAreNotDuplicates12308(t *testing.T) {
	diff := `routing-options { static { route 10.5.0.0/16 { qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; } qualified-next-hop 10.0.0.3 { preference 250; } } } }`
	tree, perrs := NewParser(diff).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("two distinct QNH gateways must commit clean, got: %v", err)
	}
	t2, _ := NewParser(diff).Parse()
	cfg, err := CompileConfigLenient(t2)
	if err != nil || cfg == nil {
		t.Fatalf("lenient: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "qualified-next-hop") {
			t.Errorf("two distinct QNH gateways must not warn, got: %q", w)
		}
	}

	flat := flatTreeFromSets(t,
		"set routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 interface ge-0/0/0.0",
		"set routing-options static route 10.5.0.0/16 qualified-next-hop 10.0.0.2 preference 250",
	)
	fc, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("flat same-gateway lines must commit clean, got: %v", err)
	}
	if len(fc.RoutingOptions.StaticRoutes) != 1 || len(fc.RoutingOptions.StaticRoutes[0].NextHops) != 1 {
		t.Fatalf("flat same-gateway lines must merge to one next-hop, got %+v", fc.RoutingOptions.StaticRoutes)
	}
}

// The rib-scoped static route compiles through the same loop, so it splits
// the same way and needs the same report.
func TestReopenedRibQualifiedNextHopIsReported12308(t *testing.T) {
	const dup = `routing-options { rib inet.0 { static { route 10.5.0.0/16 { qualified-next-hop 10.0.0.2 { interface ge-0/0/0.0; } qualified-next-hop 10.0.0.2 { preference 250; } } } } }`
	tree, errs := NewParser(dup).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a re-opened rib qualified-next-hop still COMMITS CLEAN (#12308)")
	}
	t2, _ := NewParser(dup).Parse()
	cfg, err := CompileConfigLenient(t2)
	if err != nil || cfg == nil {
		t.Fatalf("the tolerant path must not hard-fail: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "qualified-next-hop") {
			return
		}
	}
	t.Error("the tolerant path splits the rib backup into two tiers and reports nothing (#12308)")
}
