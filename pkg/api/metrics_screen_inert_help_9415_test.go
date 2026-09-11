package api

import (
	"strings"
	"testing"
)

// #9415 member 1, third surface: the xpf_screen_inert_profile_zones HELP said the
// dataplane "enforces nothing for the zone" and then appended a Disposition
// saying it enforces the substituted conservative default (#7888). The
// Disposition is the true one.
func TestScreenInertProfileHelpDoesNotClaimNothingEnforced_9415(t *testing.T) {
	help := newCollector(&Server{}).screenInertProfileZones.String()
	if !strings.Contains(help, "xpf_screen_inert_profile_zones") {
		t.Fatalf("precondition: wrong descriptor: %s", help)
	}
	if strings.Contains(help, "enforces nothing") {
		t.Errorf("HELP still claims nothing is enforced, contradicting its own Disposition: %s", help)
	}
	if !strings.Contains(help, "substituted conservative default") {
		t.Errorf("HELP must keep the substituted-default Disposition: %s", help)
	}
}
