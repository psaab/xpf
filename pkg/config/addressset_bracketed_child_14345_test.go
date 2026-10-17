package config

import (
	"reflect"
	"testing"
)

// #14345: a bracketed child block inside an address-set —
// `address { [ a1 a2 ]; }` / `address-set { [ sub1 sub2 ]; }` — collapses
// onto ONE child node whose Keys carry every member token. The child loop
// in addressSetMemberValues read only vn.Keys[0], so every member after
// the first was silently dropped with 0 errors / 0 warnings, under-
// matching deny/reject policies and NAT rules that reference the set
// (fail-open). Both the global and zone-local books share
// parseAddressBookEntries and are covered.
func TestAddressSetBracketedChildBlockMembersPreserved(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		zone bool // read the set from the zone-local book instead of global
	}{
		{
			name: "global",
			text: `security { address-book { global {
				address a1 10.0.0.1/32;
				address a2 10.0.0.2/32;
				address-set sub1 { address a1; }
				address-set sub2 { address a2; }
				address-set s1 { address { [ a1 a2 ]; } address-set { [ sub1 sub2 ]; } }
			} } }`,
		},
		{
			name: "zone-local",
			zone: true,
			text: `security { zones { security-zone trust { address-book {
				address a1 10.0.0.1/32;
				address a2 10.0.0.2/32;
				address-set sub1 { address a1; }
				address-set sub2 { address a2; }
				address-set s1 { address { [ a1 a2 ]; } address-set { [ sub1 sub2 ]; } }
			} } } }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := CompileConfig(tr)
			if err != nil {
				t.Fatalf("CompileConfig (strict): %v", err)
			}
			if len(cfg.Warnings) > 0 {
				t.Fatalf("CompileConfig warnings = %v, want none", cfg.Warnings)
			}
			var book *AddressBook
			if tc.zone {
				for _, z := range cfg.Security.Zones {
					if z.AddressBook != nil {
						book = z.AddressBook
					}
				}
			} else {
				book = cfg.Security.AddressBook
			}
			if book == nil {
				t.Fatalf("address book missing")
			}
			s1 := book.AddressSets["s1"]
			if s1 == nil {
				t.Fatalf("address-set s1 missing from compiled address book")
			}
			if want := []string{"a1", "a2"}; !reflect.DeepEqual(s1.Addresses, want) {
				t.Fatalf("s1 addresses = %v, want %v (bracketed child block tail dropped — #14345)", s1.Addresses, want)
			}
			if want := []string{"sub1", "sub2"}; !reflect.DeepEqual(s1.AddressSets, want) {
				t.Fatalf("s1 nested sets = %v, want %v (bracketed child block tail dropped — #14345)", s1.AddressSets, want)
			}
		})
	}
}
