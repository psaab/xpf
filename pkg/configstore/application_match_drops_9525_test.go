package configstore

import (
	"strings"
	"testing"
)

// TestCheckTextNamesTheICMPIdentifier9525 pins the corrected commit-check text
// on the operator-facing channel: a source-port on icmp is matched against the
// sender-chosen ICMP query Identifier, not a port that is always 0.
func TestCheckTextNamesTheICMPIdentifier9525(t *testing.T) {
	text := `applications { application a { protocol icmp; source-port 80; } } ` +
		`security { zones { security-zone trust; security-zone untrust; } policies { ` +
		`default-policy { permit-all; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address any; destination-address any; application a; } then { deny; } } } } }`
	_, err := CheckText(text, 0)
	if err == nil {
		t.Fatal("CheckText must reject a source-port on icmp")
	}
	if !strings.Contains(err.Error(), "ICMP query Identifier") || strings.Contains(err.Error(), "always 0") {
		t.Fatalf("CheckText must name the ICMP query Identifier and not claim ports are always 0; got %v", err)
	}
	ok := strings.Replace(text, "source-port 80; ", "", 1)
	if _, err := CheckText(ok, 0); err != nil {
		t.Fatalf("control: the same application without the port must pass CheckText: %v", err)
	}
}
