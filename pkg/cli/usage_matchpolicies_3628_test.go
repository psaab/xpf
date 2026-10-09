package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestShowMatchPoliciesUsageAdvertisesSelectors is the #3628 call-site
// RED-on-revert guard for the LOCAL CLI `show security match-policies`. With the
// required from-zone/to-zone missing, the command prints its usage/help block.
// That block must advertise every selector the parser accepts (source-port,
// icmp-type, icmp-code, protocol by name/number) — the local surface was the
// worst offender pre-#3628, advertising only
// "source-ip destination-ip destination-port protocol <tcp|udp>".
//
// FAIL-ON-REVERT: restoring the stale two-line usage (bypassing the shared
// policymatch constant) drops these tokens and fails the assertions.
func TestShowMatchPoliciesUsageAdvertisesSelectors(t *testing.T) {
	c := &CLI{}
	out := captureStdout(t, func() {
		// Empty args -> missing from-zone/to-zone -> usage is printed before any
		// store/dataplane access, so a bare CLI + empty config suffices.
		if err := c.showMatchPolicies(&config.Config{}, nil); err != nil {
			t.Fatalf("showMatchPolicies: %v", err)
		}
	})

	if strings.Contains(out, "protocol <tcp|udp>") {
		t.Fatalf("show security match-policies still prints the stale tcp|udp-only usage:\n%s", out)
	}
	for _, tok := range []string{
		"source-port", "destination-port", "icmp-type", "icmp-code", "icmp6",
		"omitted source/destination IP matches", "any address.",
		"An omitted protocol, port, or icmp-type/code never matches",
		"a term constrained on that dimension; unconstrained terms may match.",
		"A verdict for a partly specified query is not exhaustive — a skipped",
		"deny can let a later permit match.",
	} {
		if !strings.Contains(out, tok) {
			t.Fatalf("show security match-policies usage missing %q:\n%s", tok, out)
		}
	}
}
