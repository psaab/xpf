package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14363: the local CLI `show security policies` STANDARD view (the
// non-brief/non-detail dispatcher branch in cli_show_security_dispatch.go)
// rendered quarantined zone-pair and global rules with raw zone names and
// plain State: enabled, even though the brief branch in the same function
// and the detail view qualify quarantined zones
// (config.ZoneQuarantinePoliciesQualifier) so a scrubbed rule cannot read
// as live enforcement. These are the fail-on-revert guards: dropping the
// qualifyZone/qualifyScopeLabel calls in the standard branch goes RED.

func Test_14363_StandardViewQualifiesQuarantinedZones(t *testing.T) {
	c := briefQuarantineCLI12901(t)
	out := captureStdout(t, func() {
		if err := c.handleShowSecurity([]string{"policies"}); err != nil {
			t.Fatalf("handleShowSecurity(policies): %v", err)
		}
	})

	// Quarantined zone-pair: the To-zone header carries the qualifier, so
	// its rules cannot read as ordinary live enforcement.
	if !strings.Contains(out, "From zone: trust, To zone: z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("standard view did not qualify the quarantined zone-pair header "+
			"(want \"To zone: z214 %s\"):\n%s", config.ZoneQuarantinePoliciesQualifier, out)
	}

	// Quarantine-dropped scoped global: its to-zone scope member is
	// qualified (its unscoped from side stays the plain "any" placeholder).
	dropped := flatPolicyBlock(t, out, "dropped-global")
	if !strings.Contains(dropped, "To zones: z214 "+config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("dropped-global block = %q, want the quarantined to-zone qualifier "+
			"(standard view rendered a scrubbed global as live — #14363 regression)", dropped)
	}
	if !strings.Contains(dropped, "From zones: any") {
		t.Fatalf("dropped-global block = %q, want the unscoped from side to stay \"any\"", dropped)
	}

	// Controls: live rules keep their historical unqualified rendering.
	if !strings.Contains(out, "From zone: trust, To zone: trust\n") {
		t.Fatalf("standard view lost the ordinary trust->trust header:\n%s", out)
	}
	if ordinary := flatPolicyBlock(t, out, "ordinary-rule"); strings.Contains(ordinary, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary-rule block = %q, live rule must not carry the quarantine qualifier", ordinary)
	}
	if live := flatPolicyBlock(t, out, "live-global"); strings.Contains(live, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("live-global block = %q, unscoped live global must not carry the quarantine qualifier", live)
	}
}
