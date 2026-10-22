package config

import (
	"reflect"
	"testing"
)

// #3904 (fable-161 F-163): a routing-instance `interface [ i1 i2 ]` bracket
// list kept only the FIRST interface — the compiler read nodeVal(prop)
// (Keys[1]). The remaining ports stayed OUTSIDE the routing-instance (in the
// default table), a VRF isolation break. The compiler now reads EVERY value
// via firewallMatchValues (Keys[1:] + child nodes) into the already-plural
// RoutingInstanceConfig.Interfaces slice, in both AST shapes (#2419). The
// `interface` leaf is an opaque implicit leaf under the routing-instances
// wildcard, so the flat-set bracket already collapses onto Keys[1:] — no
// schema change is needed.
//
// fail-on-revert: restoring the nodeVal-only read leaves Interfaces with one
// element, so the two-element assertions go RED.

func riByName(t *testing.T, cfg *Config, name string) *RoutingInstanceConfig {
	t.Helper()
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == name {
			return ri
		}
	}
	t.Fatalf("routing-instance %q missing after compile", name)
	return nil
}

func TestRoutingInstanceInterfaceMultiValueFlat(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface [ ge-0/0/1 ge-0/0/2 ge-0/0/3 ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (flat routing-instance interface): %v", err)
	}
	ri := riByName(t, cfg, "VR1")
	if got, want := ri.Interfaces, []string{"ge-0/0/1", "ge-0/0/2", "ge-0/0/3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("VR1.Interfaces = %v, want %v (bracket list truncated — VRF isolation break)", got, want)
	}
}

func TestRoutingInstanceInterfaceMultiValueHierarchical(t *testing.T) {
	tree := parseHierText(t, `routing-instances {
    VR1 {
        instance-type virtual-router;
        interface [ ge-0/0/1 ge-0/0/2 ge-0/0/3 ];
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (hierarchical routing-instance interface): %v", err)
	}
	ri := riByName(t, cfg, "VR1")
	if got, want := ri.Interfaces, []string{"ge-0/0/1", "ge-0/0/2", "ge-0/0/3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hierarchical VR1.Interfaces = %v, want %v", got, want)
	}
}

// TestRoutingInstanceInterfaceSingleValue pins that the single-interface form
// (and repeated single-interface lines) still works.
func TestRoutingInstanceInterfaceSingleValue(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 interface ge-0/0/1",
		"set routing-instances VR1 interface ge-0/0/2",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (single-value routing-instance interface): %v", err)
	}
	ri := riByName(t, cfg, "VR1")
	if got, want := ri.Interfaces, []string{"ge-0/0/1", "ge-0/0/2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("VR1.Interfaces = %v, want %v", got, want)
	}
}
