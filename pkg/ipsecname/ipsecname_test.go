package ipsecname

import (
	"reflect"
	"strings"
	"testing"
)

func TestChildNamesIsOrderIndependent9624(t *testing.T) {
	a := ChildNames("vpn", []string{"x/a", "b", "x:a"})
	b := ChildNames("vpn", []string{"x:a", "x/a", "b"})
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the input order changed the names: %v vs %v", a, b)
	}
}

// #5122: two selectors of ONE VPN whose bases collide each get the disambiguator of their
// ORIGINAL name; a non-colliding base is left unchanged.
func TestChildNamesDisambiguatesWithinOneVPN9624(t *testing.T) {
	got := ChildNames("site", []string{"x/a", "x:a", "lan"})
	if got["lan"] != "site-lan" {
		t.Errorf("a non-colliding base must be unchanged, got %q", got["lan"])
	}
	for _, sel := range []string{"x/a", "x:a"} {
		want := "site-x-a-" + Disambiguator(sel)
		if got[sel] != want {
			t.Errorf("selector %q: got %q, want %q", sel, got[sel], want)
		}
	}
	if got["x/a"] == got["x:a"] {
		t.Error("colliding bases must render distinct child names")
	}
}

func TestSANamesOfANoSelectorVPNIsItsOwnName9624(t *testing.T) {
	if got := ChildNames("blue-red", nil); got != nil {
		t.Errorf("a VPN with no selector has no selector children, got %v", got)
	}
	if got := SANames("blue-red", nil); !reflect.DeepEqual(got, []string{"blue-red"}) {
		t.Errorf("SANames = %v, want the connection and child name once", got)
	}
	got := SANames("blue", []string{"red"})
	if !reflect.DeepEqual(got, []string{"blue", "blue-red"}) {
		t.Errorf("SANames = %v, want [blue blue-red]", got)
	}
}

func TestSANamesUseTheSwanctlSpelling9624(t *testing.T) {
	got := SANames("a\tb", []string{"c"})
	for _, n := range got {
		if strings.ContainsAny(n, "\t") {
			t.Errorf("SA name %q kept a C0 control; the renderer writes it as a space", n)
		}
	}
}
