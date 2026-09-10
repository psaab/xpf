package configstore

import (
	"strings"
	"testing"
)

// #9524 on the operator channel: the issue measured CheckText accepting a mixed
// address with no error and no warning.
func TestCheckTextRejectsMixedAddressValueForm9524(t *testing.T) {
	const pol = `zones { security-zone trust; security-zone untrust; } policies { from-zone trust to-zone untrust { policy d1 { match { source-address mixed; destination-address any; application any; } then { deny; } } } }`
	bad := `security { address-book { global { address mixed { 10.10.0.0/24; dns-name evil.example; } } } ` + pol + ` }`
	_, err := CheckText(bad, 0)
	if err == nil || !strings.Contains(err.Error(), `address "mixed" configures the prefix "10.10.0.0/24" and also dns-name`) {
		t.Fatalf("CheckText must reject the mixed address and name it, got %v", err)
	}
	good := `security { address-book { global { address mixed 10.10.0.0/24; } } ` + pol + ` }`
	if _, err := CheckText(good, 0); err != nil {
		t.Fatalf("control: a sole-prefix address must pass CheckText: %v", err)
	}
}
