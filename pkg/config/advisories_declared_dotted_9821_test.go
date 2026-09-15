package config

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// TestUnresolvedInterfaceRefDeclaredDotted9821 pins the D17 migration: the
// unit arm resolves through the same declared index (either spelling), so a
// double-dot ref hits its declared dotted stanza instead of being called
// undefined — which post-#11 would diverge from FRR's bind.
func TestUnresolvedInterfaceRefDeclaredDotted9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*InterfaceUnit{
			1: {Number: 1},
		}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	declared := declaredInterfaceIndex(cfg)
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"dotted unit resolves", "ge-0/0/5.0.1", ""},
		{"dotted bare resolves", "ge-0/0/5.0", ""},
		{"dash spelling resolves", "ge-0-0-5.0.1", ""},
		{"missing unit names the declared base", "ge-0/0/5.0.9", "names no configured unit on ge-0/0/5.0"},
		{"malformed unit", "ge-0/0/5.0.xx", "has an unparseable unit"},
		{"undeclared base", "ge-0/0/9.1", "names no configured interface"},
		{"undotted unit control", "ge-0/0/0.0", ""},
		{"undotted missing unit control", "ge-0/0/0.7", "names no configured unit on ge-0/0/0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unresolvedInterfaceRef(declared, tc.ref); got != tc.want {
				t.Errorf("unresolvedInterfaceRef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// TestUserspaceRxMTUOverBudgetDeclaredDotted9821 pins the D17 migration: a
// dotted unit ref resolves against its declared stanza (unit MTU match), so
// strict-reachable both-declared zone members keep their over-budget
// warnings — keyed by the declared base, not a first-cut truncation.
func TestUserspaceRxMTUOverBudgetDeclaredDotted9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*InterfaceUnit{
			10: {Number: 10, VlanID: 100, MTU: 9000},
		}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*InterfaceUnit{
			1: {Number: 1, MTU: 9000},
		}},
	}}}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"z": {Interfaces: []string{"ge-0/0/5.0.10", "ge-0/0/0.1"}},
	}
	got := userspaceRxMTUOverBudget(cfg)
	want := map[string]int{"ge-0/0/5.0": 9000, "ge-0/0/0": 9000}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("userspaceRxMTUOverBudget = %v, want %v", got, want)
	}
}

// TestContestedTrunkZonesNoFalseContest9821 pins the D17 invariant repair:
// exact-declared bare keys are excluded from unit grouping, so two trunks
// sharing a first segment do not false-contest.
func TestContestedTrunkZonesNoFalseContest9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		"p.1": {Name: "p.1", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
	}}}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"a": {Interfaces: []string{"p.0"}},
		"b": {Interfaces: []string{"p.1"}},
	}
	if got := contestedTrunkZones(cfg); len(got) != 0 {
		t.Errorf("contestedTrunkZones = %v — two distinct interfaces sharing a first segment must not contest", got)
	}
}

// TestContestedTrunkZonesDottedTrueContest9821 pins that genuine contests on
// a dotted base still report: units of one declared dotted interface in two
// zones contest under that base.
func TestContestedTrunkZonesDottedTrueContest9821(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"p.0": {Name: "p.0", Units: map[int]*InterfaceUnit{
			1: {Number: 1},
			2: {Number: 2},
		}},
	}}}
	cfg.Security.Zones = map[string]*ZoneConfig{
		"a": {Interfaces: []string{"p.0.1"}},
		"b": {Interfaces: []string{"p.0.2"}},
	}
	got := contestedTrunkZones(cfg)
	if len(got) != 1 || len(got["p.0"]) != 2 {
		t.Fatalf("contestedTrunkZones = %v — want exactly {p.0:[a b]}", got)
	}
	zones := map[string]bool{got["p.0"][0]: true, got["p.0"][1]: true}
	if !zones["a"] || !zones["b"] {
		t.Errorf("contestedTrunkZones = %v — want zones a and b under p.0", got)
	}
}

// TestVlanUnitMTUDottedSiblingOverrideAccepted9821 pins the D17 follow-up
// migration (review): the gate's reference walk resolves through the Split,
// so a dotted unit ref records its override under the DECLARED base — where
// planPhysDesired (D13-migrated) plans the parent. Shape: declared `p`
// (unitless, so DEFINED first-cut accepts strictly) + declared `p.0` (ifc
// 1400, untagged-0 1500, tagged-10 1500) + zone member `p.0.0`. Runtime
// parent runs 1500 (unit-0 override); first-cut recorded under `p`, missed
// the override, and falsely refused vs 1400.
func TestVlanUnitMTUDottedSiblingOverrideAccepted9821(t *testing.T) {
	sets := []string{
		"set interfaces p mtu 1500",
		"set interfaces p.0 mtu 1400",
		"set interfaces p.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces p.0 unit 0 family inet mtu 1500",
		"set interfaces p.0 unit 10 vlan-id 10",
		"set interfaces p.0 unit 10 family inet mtu 1500",
		"set security zones security-zone z interfaces p.0.0",
	}
	if _, err := CompileConfig(flatTreeFromSets(t, sets...)); err != nil {
		t.Fatalf("dotted sibling-override shape refused: %v (runtime parent runs 1500 — the gate must see the override)", err)
	}
}

// TestVlanUnitMTUDottedGenuineOverBudgetRefused9821 pins the gate still
// bites on dotted shapes: tagged 1600 above the override-pinned 1500 parent
// refuses.
func TestVlanUnitMTUDottedGenuineOverBudgetRefused9821(t *testing.T) {
	sets := []string{
		"set interfaces p mtu 1500",
		"set interfaces p.0 mtu 1400",
		"set interfaces p.0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces p.0 unit 0 family inet mtu 1500",
		"set interfaces p.0 unit 10 vlan-id 10",
		"set interfaces p.0 unit 10 family inet mtu 1600",
		"set security zones security-zone z interfaces p.0.0",
	}
	_, err := CompileConfig(flatTreeFromSets(t, sets...))
	if err == nil {
		t.Fatal("dotted genuine over-budget (1600 > 1500 parent) compiled — want refusal")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("refusal %q does not name the MTU excess", err)
	}
}

// TestVlanUnitMTUOverflowMatchesResolver9821 pins the review fix: a
// range-overflowed unit suffix records the SATURATED value — exactly what
// resolveInterfaceRef assigns (it ignores Atoi's error) — never unit 0.
// Zeroing here would credit an unreferenced unit-0 override the planner
// never selects. Tolerant-path-only (strict #5933 rejects garbage), but
// the gate claims all-shape agreement, so it matches bit-for-bit.
func TestVlanUnitMTUOverflowMatchesResolver9821(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"p": {Name: "p", Units: map[int]*InterfaceUnit{0: {Number: 0}}},
		}},
		Security: SecurityConfig{Zones: map[string]*ZoneConfig{
			"z": {Interfaces: []string{"p.99999999999999999999", "p", "p."}},
		}},
	}
	got := vlanUnitMTUReferencedUnits9837(cfg)
	if !got["p"][math.MaxInt] {
		t.Errorf("overflow ref records %v — want the saturated unit, as the resolver assigns", got["p"])
	}
	if len(got["p"]) != 2 {
		t.Errorf("referenced units = %v — want exactly {0 (bare+trailing), MaxInt (overflow)}", got["p"])
	}
}
