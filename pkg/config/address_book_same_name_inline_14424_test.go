package config

import "testing"

// #14424: address-book `address` identity not honoured.
//
// A group `address A <group-prefix>` must not overwrite an inline
// `address A <inline-prefix>`. Pre-fix the four leaf/container shape pairs
// resolved inconsistently — L<-L kept inline, but C<-L, L<-C and C<-C left
// both nodes in the expanded tree and parseAddressBookEntries folded them
// into one Address map entry with last-wins, so the GROUP value (adopted
// after the inline node) won. A policy referencing A then matched the
// group's prefix instead of the operator's inline prefix.
//
// #14967 supersedes the silent half of that resolution: a DISTINCT group
// prefix beside an inline one no longer resolves to either side — strict
// commit rejects the duplicate and the tolerant path refuses the entry.
// The inline prefix remains the recorded (first) value. Tests below pin
// that explicit contract; disjoint-attribute union is unchanged.
//
// FAIL-ON-REVERT: removing addressBookAddressNodes14424 registration (or
// returning false from the guard so mergeNodes falls back to adoption)
// makes the C<-L, L<-C, C<-C cells below compile A to the group prefix.
// Dropping the #14967 duplicate recording makes them commit silently.

func compileAddressBook14424(t *testing.T, text string) *AddressBook {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Security.AddressBook == nil {
		t.Fatalf("address book missing")
	}
	return cfg.Security.AddressBook
}

func TestAddressBookSameNameInlineWins14424(t *testing.T) {
	const inlinePrefix = "10.1.0.1/32"
	const groupPrefix = "10.2.0.1/32"
	cases := []struct {
		name   string
		group  string
		inline string
	}{
		{"leaf group leaf inline", "address A " + groupPrefix + ";", "address A " + inlinePrefix + ";"},
		{"container group leaf inline", "address A { " + groupPrefix + "; }", "address A " + inlinePrefix + ";"},
		{"leaf group container inline", "address A " + groupPrefix + ";", "address A { " + inlinePrefix + "; }"},
		{"container group container inline", "address A { " + groupPrefix + "; }", "address A { " + inlinePrefix + "; }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := `groups { G { security { address-book { global { ` + tc.group + ` } } } } } apply-groups G; security { address-book { global { ` + tc.inline + ` } } }`
			// #14967: a distinct group prefix no longer wins OR loses
			// silently — strict commit rejects the duplicate.
			tree := parseHierarchical(t, text)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("CompileConfig accepted group+inline distinct prefixes, want #14967 rejection")
			}
			// Tolerant path: the inline prefix stays the recorded value
			// (the #14424 precedence), but the entry refuses enforcement.
			ltree := parseHierarchical(t, text)
			cfg, err := CompileConfigLenient(ltree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			a := cfg.Security.AddressBook.Addresses["A"]
			if a == nil {
				t.Fatalf("address A missing, book=%v", cfg.Security.AddressBook.Addresses)
			}
			if a.Value != inlinePrefix {
				t.Fatalf("address A = %q, want inline %q recorded (group %q must not win)", a.Value, inlinePrefix, groupPrefix)
			}
			if a.UsableValue() != "" {
				t.Fatalf("address A usable = %q, want refused duplicate", a.UsableValue())
			}
		})
	}
}

func TestAddressBookDifferentNameBothSurvive14424(t *testing.T) {
	text := `groups { G { security { address-book { global { address B 10.2.0.2/32; } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`
	ab := compileAddressBook14424(t, text)
	if len(ab.Addresses) != 2 {
		t.Fatalf("addresses = %v, want both A and B", ab.Addresses)
	}
	if ab.Addresses["A"] == nil || ab.Addresses["A"].Value != "10.1.0.1/32" {
		t.Fatalf("A = %+v, want 10.1.0.1/32", ab.Addresses["A"])
	}
	if ab.Addresses["B"] == nil || ab.Addresses["B"].Value != "10.2.0.2/32" {
		t.Fatalf("B = %+v, want 10.2.0.2/32", ab.Addresses["B"])
	}
}

// The same identity rule applies to the zone-local address book (same
// schema shape, same parseAddressBookEntries folding).
func TestZoneLocalAddressBookSameNameInlineWins14424(t *testing.T) {
	text := `groups { G { security { zones { security-zone trust { address-book { address A 10.2.0.1/32; } } } } } } apply-groups G; security { zones { security-zone trust { address-book { address A { 10.1.0.1/32; } } } } }`
	// #14967: strict rejects the distinct group prefix (see global cells).
	tree := parseHierarchical(t, text)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("CompileConfig accepted zone-local group+inline distinct prefixes, want #14967 rejection")
	}
	ltree := parseHierarchical(t, text)
	cfg, err := CompileConfigLenient(ltree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || z.AddressBook == nil || z.AddressBook.Addresses["A"] == nil {
		t.Fatalf("zone-local address A missing: %+v", z)
	}
	if got := z.AddressBook.Addresses["A"].Value; got != "10.1.0.1/32" {
		t.Fatalf("zone-local A = %q, want inline 10.1.0.1/32 recorded", got)
	}
	if got := z.AddressBook.Addresses["A"].UsableValue(); got != "" {
		t.Fatalf("zone-local A usable = %q, want refused duplicate", got)
	}
}

// Non-conflicting attributes still union: a group description beside an
// inline prefix (and vice versa) must keep both halves, exactly as the
// pre-fix braced merge did (verified on master).
func TestAddressBookSameNameAttributesUnion14424(t *testing.T) {
	t.Run("group description inline prefix", func(t *testing.T) {
		text := `groups { G { security { address-book { global { address A { description gd; } } } } } } apply-groups G; security { address-book { global { address A 10.1.0.1/32; } } }`
		ab := compileAddressBook14424(t, text)
		a := ab.Addresses["A"]
		if a == nil || a.Value != "10.1.0.1/32" || a.Description != "gd" {
			t.Fatalf("A = %+v, want prefix 10.1.0.1/32 + description gd", a)
		}
	})
	t.Run("group prefix inline description", func(t *testing.T) {
		text := `groups { G { security { address-book { global { address A 10.2.0.1/32; } } } } } apply-groups G; security { address-book { global { address A { description id; } } } }`
		ab := compileAddressBook14424(t, text)
		a := ab.Addresses["A"]
		if a == nil || a.Value != "10.2.0.1/32" || a.Description != "id" {
			t.Fatalf("A = %+v, want group prefix 10.2.0.1/32 + inline description id", a)
		}
	})
}
