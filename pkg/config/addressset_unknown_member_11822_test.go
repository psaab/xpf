package config

import (
	"strings"
	"testing"
)

func TestAddressSetUnknownMemberRejectedOnStrictPath11822(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security address-book global address a1 10.0.0.1/32",
		"set security address-book global address-set blocked address a1",
		"set security address-book global address-set blocked addres a2",
	)
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "unknown member statement") ||
		!strings.Contains(err.Error(), "addres") {
		t.Fatalf("strict compile error = %v, want the unknown member keyword and set-poison diagnostic", err)
	}
}

func TestAddressSetUnknownMemberWarnsAndPoisonsLenientExpansion11822(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security address-book global address a1 10.0.0.1/32",
		"set security address-book global address-set blocked address a1",
		"set security address-book global address-set blocked addres a2",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must preserve bootability: %v", err)
	}
	set := cfg.Security.AddressBook.AddressSets["blocked"]
	if set == nil || len(set.UnknownMembers) != 1 || set.UnknownMembers[0] != "addres" {
		t.Fatalf("address-set unknown members = %+v, want [addres]", set)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "address-set members") &&
			strings.Contains(warning, "unknown member statement") &&
			strings.Contains(warning, "addres") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("lenient compile did not report the under-populated set: %v", cfg.Warnings)
	}
	if expanded, err := ExpandAddressSet("blocked", cfg.Security.AddressBook); err == nil {
		t.Fatalf("poisoned address-set expanded to %v without error", expanded)
	}
}

func TestZoneLocalAddressSetUnknownMemberTaintSurvivesFold11822(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security zones security-zone lan address-book address a1 10.0.0.1/32",
		"set security zones security-zone lan address-book address-set blocked address a1",
		"set security zones security-zone lan address-book address-set blocked addres a2",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	set := cfg.Security.AddressBook.AddressSets[zoneLocalQualify("lan", "blocked")]
	if set == nil || len(set.UnknownMembers) != 1 || set.UnknownMembers[0] != "addres" {
		t.Fatalf("folded zone-local set unknown members = %+v, want [addres]", set)
	}
	if _, err := ExpandAddressSet(zoneLocalQualify("lan", "blocked"), cfg.Security.AddressBook); err == nil {
		t.Fatal("folded zone-local address-set lost its poison and expanded successfully")
	}
}

func TestAddressSetDescriptionIsNotAnUnknownMember11822(t *testing.T) {
	tree := flatTreeFromSets(t,
		`set security address-book global address-set metadata description "address metadata"`,
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("address-set description was rejected: %v", err)
	}
	set := cfg.Security.AddressBook.AddressSets["metadata"]
	if set == nil || len(set.UnknownMembers) != 0 {
		t.Fatalf("valid description populated unknown members: %+v", set)
	}
}
