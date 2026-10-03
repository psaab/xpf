package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestLenientStoreWarnsAndPoisonsUnknownAddressSetMember11822(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set security address-book global address a1 10.0.0.1/32",
		"set security address-book global address-set blocked address a1",
		"set security address-book global address-set blocked addres a2",
	} {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}

	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant Store ingress must remain bootable: %v", err)
	}
	set := compiled.Security.AddressBook.AddressSets["blocked"]
	if set == nil || len(set.UnknownMembers) != 1 || set.UnknownMembers[0] != "addres" {
		t.Fatalf("stored address-set unknown members = %+v, want [addres]", set)
	}
	foundWarning := false
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, "address-set members") &&
			strings.Contains(warning, "unknown member statement") &&
			strings.Contains(warning, "addres") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("Store retained only the closed-world slog diagnostic; compiled warnings = %v", compiled.Warnings)
	}
	if expanded, err := config.ExpandAddressSet("blocked", compiled.Security.AddressBook); err == nil {
		t.Fatalf("Store returned a compiled under-populated set that expands to %v", expanded)
	}
}
