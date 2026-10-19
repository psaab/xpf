package config

import (
	"strings"
	"testing"
)

// #14967 (D30-01): address-book duplicate prefixes, apply-groups
// precedence, and trailing tokens past an address prefix silently
// narrowed the enforced set.
//
// Before the fix the compiler folded every definition of one name into a
// single Address with last-wins (or first-group-wins on the group path),
// and a trailing token riding a DROPPED group definition vanished with
// it. A policy referencing the name then enforced whichever prefix the
// fold order happened to keep, with no diagnostic on any channel.
//
// The fix records every distinct prefix in Address.DuplicatePrefixes
// (identical repeats collapse), rejects the entry at strict commit
// (validateAddressBookDuplicatePrefixStrict, pristine books before the
// zone-local fold), and refuses it on the tolerant path via
// Address.UsableValue. Group-vs-inline and group-vs-group conflicts are
// recorded through the #14424 merge hook; trailing tokens on any merged
// definition taint the entry the same way.
//
// FAIL-ON-REVERT: reverting setAddressPrefix14967 to a plain assignment
// (or dropping the strict gate dispatch) makes every strict-reject cell
// below compile cleanly to a single surviving prefix.

func dup14967(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree := parseHierarchical(t, text)
	return CompileConfig(tree)
}

func TestAddressBookDuplicatePrefixRejected14967(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"global same block", `security { address-book { global { address A 10.0.0.1/32; address A 10.0.0.2/32; } } }`},
		{"global repeated containers", `security { address-book { global { address A 10.0.0.1/32; } global { address A 10.0.0.2/32; } } }`},
		{"global two braced containers", `security { address-book { global { address A { 10.0.0.1/32; } address A { 10.0.0.2/32; } } } }`},
		{"one container two bare children", `security { address-book { global { address A { 10.0.0.1/32; 10.0.0.2/32; } } } }`},
		{"zone-local duplicate", `security { zones { security-zone trust { address-book { address A 10.0.0.1/32; address A 10.0.0.2/32; } } } }`},
		{"group vs inline distinct", `groups { G { security { address-book { global { address A 10.2.0.1/32; } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`},
		{"two groups no inline", `groups { G1 { security { address-book { global { address A 10.3.0.1/32; } } } } G2 { security { address-book { global { address A 10.4.0.1/32; } } } } } apply-groups [ G1 G2 ]; security { zones { security-zone trust; } }`},
		{"inline two bare group one", `groups { G { security { address-book { global { address A { 10.2.0.1/32; } } } } } } apply-groups G; security { address-book { global { address A { 10.1.0.1/32; 10.1.0.9/32; } } } }`},
		{"group container vs inline leaf trailing dropped", `groups { G { security { address-book { global { address A 10.2.0.1/32 bogus; } } } } } apply-groups G; security { address-book { global { address A { 10.1.0.1/32; } } } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := dup14967(t, tc.text)
			if err == nil {
				t.Fatalf("CompileConfig accepted duplicate prefixes for A (cfg=%+v), want explicit rejection", cfg)
			}
			if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "trailing") {
				t.Fatalf("error = %q, want duplicate/trailing diagnostic", err)
			}
			// Tolerant path boots but refuses the entry.
			tree := parseHierarchical(t, tc.text)
			lcfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient must boot (#1960): %v", lerr)
			}
			foundWarn := false
			for _, w := range lcfg.Warnings {
				if strings.Contains(w, "duplicate prefix") || strings.Contains(w, "trailing token") {
					foundWarn = true
				}
			}
			if !foundWarn {
				t.Fatalf("lenient warnings = %v, want duplicate/trailing warning", lcfg.Warnings)
			}
			// The entry (global or folded zone-local) must be unusable.
			checked := false
			if lcfg.Security.AddressBook != nil {
				for key, a := range lcfg.Security.AddressBook.Addresses {
					if key == "A" || strings.HasSuffix(key, "/A") {
						checked = true
						if a.UsableValue() != "" {
							t.Fatalf("lenient %q usable = %q, want refused", key, a.UsableValue())
						}
					}
				}
			}
			for _, z := range lcfg.Security.Zones {
				if z != nil && z.AddressBook != nil {
					if a := z.AddressBook.Addresses["A"]; a != nil {
						checked = true
						if a.UsableValue() != "" {
							t.Fatalf("lenient zone-local A usable = %q, want refused", a.UsableValue())
						}
					}
				}
			}
			if !checked {
				t.Fatalf("no A entry found to check usable refusal")
			}
		})
	}
}

// Controls: legitimate configurations through the same paths stay green.
func TestAddressBookDuplicateControlsGreen14967(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		wantValue string
		wantDesc  string
	}{
		{"identical repeat", `security { address-book { global { address A 10.0.0.1/32; address A 10.0.0.1/32; } } }`, "10.0.0.1/32", ""},
		{"prefix plus description split", `security { address-book { global { address A 10.0.0.1/32; address A description foo; } } }`, "10.0.0.1/32", "foo"},
		{"description plus prefix split", `security { address-book { global { address A { description foo; } address A 10.0.0.1/32; } } }`, "10.0.0.1/32", "foo"},
		{"single address", `security { address-book { global { address A 10.0.0.1/32; address B 10.0.0.2/32; } } }`, "10.0.0.1/32", ""},
		{"group disjoint description", `groups { G { security { address-book { global { address A { description gd; } } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`, "10.1.0.1/32", "gd"},
		{"group same prefix as inline", `groups { G { security { address-book { global { address A 10.1.0.1/32; } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`, "10.1.0.1/32", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := dup14967(t, tc.text)
			if err != nil {
				t.Fatalf("CompileConfig = %v, want clean commit", err)
			}
			a := cfg.Security.AddressBook.Addresses["A"]
			if a == nil {
				t.Fatalf("A missing")
			}
			if a.Value != tc.wantValue || a.UsableValue() != tc.wantValue || a.Description != tc.wantDesc {
				t.Fatalf("A = %+v, want value/usable %q desc %q", a, tc.wantValue, tc.wantDesc)
			}
			if len(a.DuplicatePrefixes) != 0 || len(a.TrailingTokens) != 0 {
				t.Fatalf("A tainted %+v, want clean", a)
			}
		})
	}
}

// A policy referencing a duplicate-tainted name fails closed on the
// tolerant path (the strict path already rejects the duplicate itself).
func TestAddressBookDuplicatePolicyRefusedLenient14967(t *testing.T) {
	text := `security { address-book { global { address A 10.0.0.1/32; address A 10.0.0.2/32; address-set S { address A; } } } zones { security-zone trust; security-zone untrust; } policies { from-zone trust to-zone untrust { policy p { match { source-address S; destination-address any; application any; } then { deny; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if got := policyMatchAddressBookResolves(cfg.Security.AddressBook, "S"); got == nil {
		t.Fatalf("set S referencing duplicate A resolved, want fail-closed")
	}
	if got := policyMatchAddressBookResolves(cfg.Security.AddressBook, "A"); got == nil {
		t.Fatalf("duplicate A resolved, want fail-closed")
	}
}

// Group-vs-inline with the SAME prefix plus a group description still
// unions (the #14424 disjoint-attribute behaviour is preserved).
func TestAddressBookGroupSamePrefixDescriptionUnion14967(t *testing.T) {
	text := `groups { G { security { address-book { global { address A { description gd; 10.1.0.1/32; } } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`
	cfg, err := dup14967(t, text)
	if err != nil {
		t.Fatalf("CompileConfig = %v, want clean union commit", err)
	}
	a := cfg.Security.AddressBook.Addresses["A"]
	if a == nil || a.Value != "10.1.0.1/32" || a.Description != "gd" {
		t.Fatalf("A = %+v, want prefix + group description", a)
	}
}
