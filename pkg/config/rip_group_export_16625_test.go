package config

import (
	"strings"
	"testing"
)

// #16625 (R3-A12-03): RIP per-group `export` was flattened into one
// global ripd redistribute chain. Two groups with different export
// policies committed strict-clean; order decided leak vs loss.
//
// Fix: compiler preserves Groups; strict gate rejects only the
// inexpressible shape (one interface in 2+ groups with differing
// exports); lenient warns (#1960). The renderer (pkg/frr) enforces
// per-interface filtering — see rip_group_export_16625_test.go
// there.
//
// fail-on-revert: dropping Groups capture makes the association
// assertions RED; dropping the gate makes the contested cells RED.

func ripGroupProbe16625(t *testing.T, customersFirst bool) []string {
	t.Helper()
	policies := []string{
		"set policy-options policy-statement DEFAULT-ONLY term t1 from route-filter 0.0.0.0/0 exact",
		"set policy-options policy-statement DEFAULT-ONLY term t1 then accept",
		"set policy-options policy-statement ALL-STATIC term t1 from route-filter 192.168.50.0/24 exact",
		"set policy-options policy-statement ALL-STATIC term t1 then accept",
	}
	cust := []string{
		"set protocols rip group CUSTOMERS export DEFAULT-ONLY",
		"set protocols rip group CUSTOMERS neighbor ge-0/0/1.0",
	}
	core := []string{
		"set protocols rip group CORE export ALL-STATIC",
		"set protocols rip group CORE neighbor ge-0/0/2.0",
	}
	lines := append([]string{}, policies...)
	if customersFirst {
		lines = append(lines, cust...)
		lines = append(lines, core...)
	} else {
		lines = append(lines, core...)
		lines = append(lines, cust...)
	}
	return lines
}

func TestRIPGroupExportAssociationPreserved16625(t *testing.T) {
	for _, customersFirst := range []bool{true, false} {
		cfg, err := CompileConfig(flatTreeFromSets(t, ripGroupProbe16625(t, customersFirst)...))
		if err != nil {
			t.Fatalf("customersFirst=%v: probe must commit strict-clean now that per-group export is modelled: %v", customersFirst, err)
		}
		rip := cfg.Protocols.RIP
		if rip == nil || len(rip.Groups) != 2 {
			t.Fatalf("customersFirst=%v: Groups=%v, want 2 groups", customersFirst, rip)
		}
		byName := map[string]*RIPGroup{}
		for _, g := range rip.Groups {
			byName[g.Name] = g
		}
		cust, core := byName["CUSTOMERS"], byName["CORE"]
		if cust == nil || core == nil {
			t.Fatalf("customersFirst=%v: groups=%v", customersFirst, rip.Groups)
		}
		if len(cust.Export) != 1 || cust.Export[0] != "DEFAULT-ONLY" || len(cust.Interfaces) != 1 || cust.Interfaces[0] != "ge-0/0/1.0" {
			t.Errorf("CUSTOMERS=%+v, want export=[DEFAULT-ONLY] ifaces=[ge-0/0/1.0]", cust)
		}
		if len(core.Export) != 1 || core.Export[0] != "ALL-STATIC" || len(core.Interfaces) != 1 || core.Interfaces[0] != "ge-0/0/2.0" {
			t.Errorf("CORE=%+v, want export=[ALL-STATIC] ifaces=[ge-0/0/2.0]", core)
		}
	}
}

func TestRIPGroupExportContestedInterfaceRejected16625(t *testing.T) {
	lines := []string{
		"set policy-options policy-statement P1 term t1 then accept",
		"set policy-options policy-statement P2 term t1 then accept",
		"set protocols rip group A export P1",
		"set protocols rip group A neighbor ge-0/0/1.0",
		"set protocols rip group B export P2",
		"set protocols rip group B neighbor ge-0/0/1.0",
	}
	_, err := CompileConfig(flatTreeFromSets(t, lines...))
	if err == nil {
		t.Fatal("strict must reject one interface in two groups with different exports")
	}
	if !strings.Contains(err.Error(), "ge-0/0/1.0") || !strings.Contains(err.Error(), "#16625") {
		t.Errorf("refusal must name interface + issue: %v", err)
	}
	lenientCfg, lenientErr := CompileConfigLenient(flatTreeFromSets(t, lines...))
	if lenientErr != nil {
		t.Fatalf("lenient must boot (#1960): %v", lenientErr)
	}
	var warned bool
	for _, w := range lenientCfg.Warnings {
		if strings.Contains(w, "ge-0/0/1.0") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("lenient must warn naming contested interface; warnings=%v", lenientCfg.Warnings)
	}
	if got := RIPContestedInterfaces16625(lenientCfg.Protocols.RIP); len(got) != 1 || got[0] != "ge-0/0/1.0" {
		t.Errorf("RIPContestedInterfaces16625=%v, want [ge-0/0/1.0]", got)
	}
}

func TestRIPGroupExportSamePolicyTwoGroupsAccepted16625(t *testing.T) {
	lines := []string{
		"set policy-options policy-statement P1 term t1 then accept",
		"set protocols rip group A export P1",
		"set protocols rip group A neighbor ge-0/0/1.0",
		"set protocols rip group B export P1",
		"set protocols rip group B neighbor ge-0/0/1.0",
		"set protocols rip group B neighbor ge-0/0/2.0",
	}
	cfg, err := CompileConfig(flatTreeFromSets(t, lines...))
	if err != nil {
		t.Fatalf("identical exports must commit: %v", err)
	}
	if got := RIPContestedInterfaces16625(cfg.Protocols.RIP); len(got) != 0 {
		t.Errorf("identical exports must not be contested: %v", got)
	}
}

func TestRIPGroupExportRoutingInstanceContested16625(t *testing.T) {
	lines := []string{
		"set policy-options policy-statement P1 term t1 then accept",
		"set policy-options policy-statement P2 term t1 then accept",
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A protocols rip group A export P1",
		"set routing-instances VRF-A protocols rip group A neighbor ge-0/0/1.0",
		"set routing-instances VRF-A protocols rip group B export P2",
		"set routing-instances VRF-A protocols rip group B neighbor ge-0/0/1.0",
	}
	_, err := CompileConfig(flatTreeFromSets(t, lines...))
	if err == nil || !strings.Contains(err.Error(), "VRF-A") {
		t.Fatalf("RI contested must reject naming instance: %v", err)
	}
}

func TestRIPGroupExportSingleAndNoGroupUnaffected16625(t *testing.T) {
	for _, lines := range [][]string{
		{"set protocols rip neighbor ge-0/0/1.0", "set protocols rip redistribute static"},
		{
			"set policy-options policy-statement P1 term t1 then accept",
			"set protocols rip group A export P1",
			"set protocols rip group A neighbor ge-0/0/1.0",
		},
	} {
		if _, err := CompileConfig(flatTreeFromSets(t, lines...)); err != nil {
			t.Fatalf("control must commit: %v (lines=%v)", err, lines)
		}
	}
}
