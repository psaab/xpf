package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestFabricBondPoisonedRefNeverReachesRender_9886 is the compile→model→render
// regression for the #9886 reconstruction close. A bond whose member list
// names a render-unsafe identity compiles leniently (the reference is
// stripped in the prewalk); the model builder must then emit NO row for the
// poisoned name — fully inert, not a refused-but-partially-applied row. The
// model→render leg needs no stubbed Apply here: absence from ManagedInterfaces
// means the networkd belt never sees the name, and the belt's own tests pin
// refusal if one ever arrived.
func TestFabricBondPoisonedRefNeverReachesRender_9886(t *testing.T) {
	tree, errs := config.NewParser(`interfaces {
  fab0 {
    fabric-options { member-interfaces [ "ge 0" ge-0/0/7 ge-7/0/7 ]; }
    unit 0 { family inet { address 10.99.1.1/30; } }
  }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	for _, m := range cfg.Interfaces.Interfaces["fab0"].FabricMembers {
		if m == "ge 0" {
			t.Fatal(`compile leg: "ge 0" must be stripped from FabricMembers`)
		}
	}

	result := &CompileResult{ifCache: map[string]*net.Interface{}}
	buildFabricBondModels(cfg, result, map[string]bool{})
	for _, mi := range result.ManagedInterfaces {
		if mi.Name == "ge 0" || strings.Contains(mi.Name, " ") {
			t.Fatalf("model leg: poisoned row %q emitted for a stripped reference", mi.Name)
		}
	}
	foundBond, foundMember := false, false
	for _, mi := range result.ManagedInterfaces {
		if mi.Name == "fab0" && mi.IsBond {
			foundBond = true
		}
		if mi.BondMaster == "fab0" {
			foundMember = true
		}
	}
	if !foundBond || !foundMember {
		t.Fatalf("model leg: clean bond + surviving members must still emit (bond=%v member=%v): %+v",
			foundBond, foundMember, result.ManagedInterfaces)
	}
}
