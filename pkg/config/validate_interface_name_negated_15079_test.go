package config

import (
	"strings"
	"testing"
)

// TestValidateInterfaceNameRejectsNegated_15079 is the commit-time half of
// the #15079 belt. A leading '!' is not in the interface-name allowlist, so
// it was already refused before this change — but only with the generic
// "contains '!'" message, which does not tell the operator the rendered
// [Match] Name= value would claim every interface except the named one.
// The refusal must now name that consequence and cite #15079. Reverting
// the dedicated prefix branch makes the message assertions below FAIL
// while the refusal itself stays — this test pins the diagnosis, not
// merely the error.
func TestValidateInterfaceNameRejectsNegated_15079(t *testing.T) {
	for _, name := range []string{"!eth0", "!!eth0", "!x", "!"} {
		err := ValidateInterfaceName(name, nil)
		if err == nil {
			t.Errorf("ValidateInterfaceName(%q) must REJECT — it would claim every interface except the named one", name)
			continue
		}
		for _, want := range []string{"begins with '!'", "inverting the match list", "every interface except the named one", "#15079", "[Match] Name="} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ValidateInterfaceName(%q) error must mention %q, got %v", name, want, err)
			}
		}
		if strings.Contains(err.Error(), "allowed characters are") {
			t.Errorf("ValidateInterfaceName(%q) fell through to the generic allowlist message: %v", name, err)
		}
	}
	// Controls: a '!' anywhere but the lead is still refused (it is not in
	// the allowlist), and ordinary names still commit.
	for _, name := range []string{"eth0!", "e!th0"} {
		if err := ValidateInterfaceName(name, nil); err == nil {
			t.Errorf("ValidateInterfaceName(%q) must still REJECT (not allowlisted)", name)
		}
	}
	for _, name := range []string{"ge-0/0/0", "ge-0-0-0", "reth0.50", "fxp0"} {
		if err := ValidateInterfaceName(name, nil); err != nil {
			t.Errorf("ValidateInterfaceName(%q) control must ACCEPT, got %v", name, err)
		}
	}
}
