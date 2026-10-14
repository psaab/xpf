// #12852 (D4-05): canonicalizeParsedAddressBookContent bucketed by masked
// (IP, ones) while buildAddressBookTableWithFeeds kept the raw wire strings
// of the alphabetically first name. "10.0.0.0/008" (helper-refused padded
// mask, #12507) and "10.0.0.0/8" therefore shared one bucket: an
// unreferenced padded entry poisoned a clean referenced one (whole snapshot
// refused), and a clean first entry masked a referenced padded one (no
// refusal). The bucket key now carries helper-refused wire spellings, so a
// refused spelling never shares a row with its canonical spelling
// (helper-accepted padding still shares by design, #12178).
package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Case 1: an unreferenced padded entry must not poison a clean referenced
// entry. On buggy code both names share one bucket whose row carries
// "10.0.0.0/008", so the refusal names the shared row.
func TestAddressBookWireSpellingNotConflated12852(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		AddressBook: &config.AddressBook{Addresses: map[string]*config.Address{
			"a_padded": {Name: "a_padded", Value: "10.0.0.0/008"},
			"z_clean":  {Name: "z_clean", Value: "10.0.0.0/8"},
		}},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{{
				Name: "p1",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"z_clean"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			}},
		}},
	}}
	books, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("buildAddressBookTable: %v", err)
	}
	if nameToID["a_padded"] == 0 || nameToID["z_clean"] == 0 {
		t.Fatalf("both names need IDs: %v", nameToID)
	}
	if nameToID["a_padded"] == nameToID["z_clean"] {
		t.Fatalf("padded and clean spellings must not share a book ID: %v", nameToID)
	}
	for _, book := range books {
		if book.ID == nameToID["z_clean"] {
			for _, p := range book.PrefixesV4 {
				if p != "10.0.0.0/8" {
					t.Fatalf("clean book row carries %q, want 10.0.0.0/8", p)
				}
			}
		}
		if book.ID == nameToID["a_padded"] {
			found := false
			for _, p := range book.PrefixesV4 {
				if p == "10.0.0.0/008" {
					found = true
				}
			}
			if !found {
				t.Fatalf("padded book row lost its wire spelling: %+v", book)
			}
		}
	}
	// The refusal must name only the padded name, never the clean one.
	reasons := collectAddressBookCIDRMaskRejections(books)
	foundPadded := false
	for _, r := range reasons {
		if strings.Contains(r, `"z_clean"`) {
			t.Fatalf("clean entry poisoned by padded alias: %v", reasons)
		}
		if strings.Contains(r, `"a_padded"`) && strings.Contains(r, "10.0.0.0/008") {
			foundPadded = true
		}
	}
	if !foundPadded {
		t.Fatalf("padded entry must be named in refusal, got %v", reasons)
	}
}

// Case 2: a clean first entry must not mask a referenced padded entry.
// On buggy code the shared bucket carries "10.0.0.0/8" and no refusal fires.
func TestAddressBookPaddedSpellingNotMasked12852(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		AddressBook: &config.AddressBook{Addresses: map[string]*config.Address{
			"a_clean":  {Name: "a_clean", Value: "10.0.0.0/8"},
			"z_padded": {Name: "z_padded", Value: "10.0.0.0/008"},
		}},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{{
				Name: "p1",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"z_padded"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
				Action: config.PolicyPermit,
			}},
		}},
	}}
	books, nameToID, err := buildAddressBookTable(cfg)
	if err != nil {
		t.Fatalf("buildAddressBookTable: %v", err)
	}
	if nameToID["a_clean"] == nameToID["z_padded"] {
		t.Fatalf("clean and padded spellings must not share a book ID: %v", nameToID)
	}
	reasons := collectAddressBookCIDRMaskRejections(books)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, `"a_clean"`) {
			t.Fatalf("clean entry wrongly refused: %v", reasons)
		}
		if strings.Contains(r, `"z_padded"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("referenced padded entry masked by clean alias, reasons=%v", reasons)
	}
}
