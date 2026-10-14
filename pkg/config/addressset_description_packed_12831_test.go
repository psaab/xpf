package config

import (
	"sort"
	"strings"
	"testing"
)

// #12831 (D2-07): `address` / `address-set` definitions packed or braced with
// `description` were silently discarded.
//
//   - address-set: the `description` child/leaf was treated as pure metadata
//     and the tokens packed after it (braced: leaf Keys[description d address
//     a1]; elided: tail on the address-set node) were never examined, so the
//     first member after a description vanished. A set could compile as a
//     valid nonempty set narrowed to only its later members.
//   - address: `address a1 { description "d" 10.0.0.1/32; }` (and the
//     packed spelling) routed the whole leaf to Description and returned
//     before seeing the prefix, leaving Value empty.
//
// Both spellings (packed/elided and braced) must compile identically to the
// plain separated spelling.
func compileBook12831(t *testing.T, text string) *AddressBook {
	t.Helper()
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg.Security.AddressBook
}

func setMembers12831(ab *AddressBook, name string) (addrs, sets []string) {
	s := ab.AddressSets[name]
	if s == nil {
		return nil, nil
	}
	return append([]string(nil), s.Addresses...), append([]string(nil), s.AddressSets...)
}

func TestAddressSetDescriptionPackedMembers12831(t *testing.T) {
	const prefix = `security { address-book { global { address a1 10.0.0.1/32; address a2 10.0.0.2/32; address-set inner { address a1; } `

	cases := []struct {
		name      string
		body      string
		wantAddrs []string
		wantSets  []string
	}{
		{"braced description first then packed member", `address-set S { description "d" address a1; address a2; } } } }`, []string{"a1", "a2"}, nil},
		{"braced description then members", `address-set S { description "d"; address a1; address a2; } } } }`, []string{"a1", "a2"}, nil},
		{"braced description between members", `address-set S { address a1; description "d" address a2; } } } }`, []string{"a1", "a2"}, nil},
		{"elided description then members", `address-set S description "d" address a1; } } }`, []string{"a1"}, nil},
		{"elided nested set after description", `address-set S description "d" address-set inner; } } }`, nil, []string{"inner"}},
		{"braced nested set after description", `address-set S { description "d" address-set inner; address a1; } } } }`, []string{"a1"}, []string{"inner"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ab := compileBook12831(t, prefix+tc.body)
			gotA, gotS := setMembers12831(ab, "S")
			if strings.Join(gotA, ",") != strings.Join(tc.wantAddrs, ",") {
				t.Errorf("Addresses=%v want %v", gotA, tc.wantAddrs)
			}
			if strings.Join(gotS, ",") != strings.Join(tc.wantSets, ",") {
				t.Errorf("AddressSets=%v want %v", gotS, tc.wantSets)
			}
			if s := ab.AddressSets["S"]; s != nil && len(s.UnknownMembers) != 0 {
				t.Errorf("UnknownMembers=%v, description-packed members must not be poisoned as unknown", s.UnknownMembers)
			}
		})
	}
}

func TestAddressDescriptionPackedPrefix12831(t *testing.T) {
	cases := []struct{ name, body, wantVal, wantDesc string }{
		{"braced description then prefix", `address a1 { description "d" 10.0.0.1/32; }`, "10.0.0.1/32", "d"},
		{"packed description then prefix", `address a1 description "d" 10.0.0.1/32;`, "10.0.0.1/32", "d"},
		{"braced separated (control)", `address a1 { description "d"; 10.0.0.1/32; }`, "10.0.0.1/32", "d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ab := compileBook12831(t, `security { address-book { global { `+tc.body+` } } }`)
			a := ab.Addresses["a1"]
			if a == nil {
				t.Fatalf("address a1 missing")
			}
			if a.Value != tc.wantVal || a.Description != tc.wantDesc {
				t.Errorf("got Value=%q Desc=%q want Value=%q Desc=%q", a.Value, a.Description, tc.wantVal, tc.wantDesc)
			}
		})
	}
}

func TestAddressSetEmptyAndZoneLocal12831(t *testing.T) {
	// Empty-braces / description-only sets stay empty (no phantom members).
	ab := compileBook12831(t, `security { address-book { global { address-set S { description "d"; } address-set E { } } } }`)
	if got, _ := setMembers12831(ab, "S"); len(got) != 0 {
		t.Errorf("description-only set got members %v", got)
	}
	if got, _ := setMembers12831(ab, "E"); len(got) != 0 {
		t.Errorf("empty set got members %v", got)
	}
	// Zone-local book (same grammar, separate declaration).
	tr, perrs := NewParser(`security { zones { security-zone trust { address-book { address a1 10.0.0.1/32; address-set S { description "d" address a1; } } } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var names []string
	for _, z := range cfg.Security.Zones {
		if z.AddressBook != nil {
			if got, _ := setMembers12831(z.AddressBook, "S"); len(got) == 1 && got[0] == "a1" {
				names = append(names, z.Name)
			}
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Errorf("zone-local braced description-packed member lost")
	}
	_ = names
}

func TestAddressSetDescriptionPackedFailsClosed12831(t *testing.T) {
	ab := compileBook12831(t, `security { address-book { global { address a1 10.0.0.1/32; address a2 10.0.0.2/32; address-set S { description "d" address [ a1 a2 ]; } address-set T { description "d" typo x address a1; } address-set K { description "d" address [ description a1 ]; } } } }`)
	if got, _ := setMembers12831(ab, "S"); strings.Join(got, ",") != "a1,a2" {
		t.Errorf("bracket-list members after description=%v, want [a1 a2]", got)
	}
	s := ab.AddressSets["T"]
	if s == nil || len(s.UnknownMembers) == 0 {
		t.Errorf("unrecognized packed tail did not poison address-set T: %+v", s)
	}
	if got, _ := setMembers12831(ab, "K"); strings.Join(got, ",") != "description,a1" {
		t.Errorf("bracketed keyword-named address member=%v, want [description a1]", got)
	}
}
