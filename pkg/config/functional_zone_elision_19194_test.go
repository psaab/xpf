package config

import (
	"reflect"
	"testing"
)

// #19194: the doubly-elided `security zones functional-zone management { ... }`
// must compile exactly like the braced spelling. Before the admission it
// compiled to the EMPTY row: the management zone and its interface vanished.
// The EMPTY row keeps a SAME verdict from being vacuous.
func TestFunctionalZoneDoublyElidedCompilesLikeBraced19194(t *testing.T) {
	pre := "interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } } "
	compile := func(src string) *Config {
		t.Helper()
		tree, perr := NewParser(src).Parse()
		if perr != nil {
			t.Fatalf("parse %q: %v", src, perr)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", src, err)
		}
		return cfg
	}
	empty := compile(pre)
	braced := compile(pre + "security { zones { functional-zone management { interfaces { ge-0/0/0.0; } } } }")
	elided := compile(pre + "security zones functional-zone management { interfaces { ge-0/0/0.0; } }")
	if reflect.DeepEqual(braced.Security, empty.Security) {
		t.Fatal("fixture: the braced functional-zone compiled to the EMPTY row; the comparison would be vacuous")
	}
	if !reflect.DeepEqual(elided.Security, braced.Security) {
		t.Fatalf("doubly-elided functional-zone compiled differently from braced (EMPTY-equivalent: %v)",
			reflect.DeepEqual(elided.Security, empty.Security))
	}
	// The thing that vanished, named directly.
	z := elided.Security.Zones["management"]
	if z == nil || len(z.Interfaces) == 0 {
		t.Fatalf("the elided spelling lost the management zone or its interfaces: %+v", z)
	}
}
