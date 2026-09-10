package configstore

import (
	"strings"
	"testing"
)

// #9523 on the operator channel. The issue measured configstore.CheckText
// accepting an address named `any` with no error and no warning.
func TestCheckTextRejectsAnAddressNamedAny9523(t *testing.T) {
	const bad = `security { address-book { global { address any 10.99.0.0/16; } } zones { security-zone trust; } }`
	_, err := CheckText(bad, 0)
	if err == nil || !strings.Contains(err.Error(), `address "any" uses a reserved name`) {
		t.Fatalf("CheckText must reject an address named any and name it, got %v", err)
	}
	good := strings.Replace(bad, "address any ", "address anyhost ", 1)
	if _, err := CheckText(good, 0); err != nil {
		t.Fatalf("control: an ordinary name must pass CheckText: %v", err)
	}
}
