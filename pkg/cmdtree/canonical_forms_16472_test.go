package cmdtree

import (
	"strings"
	"testing"
)

// #16472: the shared form derivation. CanonicalForms moved here from
// pkg/cli so every gate judges the same spellings; these cells pin
// the derivations the remote gates depend on.

func TestCanonicalFormsForCharge16472(t *testing.T) {
	for _, tc := range []struct {
		charge     string
		base, full string
		sels       []string
		ok         bool
	}{
		{"show firewall filter", "show firewall", "show firewall", []string{"show firewall filter"}, true},
		{"show security screen statistics zone", "show security screen statistics", "show security screen statistics", []string{"show security screen statistics zone"}, true},
		{"show route table", "show route", "show route", []string{"show route table"}, true},
		{"show security screen ids-option", "show security screen", "show security screen", []string{"show security screen ids-option"}, true},
		{"show security zones detail", "show security zones detail", "show security zones detail", nil, true},
		{"show route", "show route", "show route", nil, true},
		{"show version", "show version", "show version", nil, true},
		{"bogus command here", "", "", nil, false},
	} {
		base, full, sels, ok := CanonicalFormsForCharge(tc.charge)
		if ok != tc.ok || base != tc.base || full != tc.full || strings.Join(sels, "|") != strings.Join(tc.sels, "|") {
			t.Errorf("CanonicalFormsForCharge(%q) = (%q,%q,%v,%v), want (%q,%q,%v,%v)",
				tc.charge, base, full, sels, ok, tc.base, tc.full, tc.sels, tc.ok)
		}
	}
	// Every registry charge must derive (the flows charge, whose bare
	// spelling does not canonicalise, is the one documented exception
	// and falls back to the charge alone at the gates).
}

func TestCanonicalFormsMovedFromCLI16472(t *testing.T) {
	// The console's documented forms for the #15942 cells.
	canon, res := Canonicalize(OperationalTree, strings.Fields("show security policies from-zone trust"))
	if res != CanonicalOK {
		t.Fatal("fixture does not canonicalise")
	}
	base, full, sels, _ := CanonicalForms(canon)
	if base != "show security policies" || full != "show security policies" ||
		len(sels) != 1 || sels[0] != "show security policies from-zone" {
		t.Errorf("CanonicalForms(policies from-zone) = (%q,%q,%v), want base/full show security policies, sel [show security policies from-zone]", base, full, sels)
	}
	if got := CanonicalPrefix(canon); got != "show security policies" {
		t.Errorf("CanonicalPrefix = %q", got)
	}
}
