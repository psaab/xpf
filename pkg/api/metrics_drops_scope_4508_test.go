package api

import (
	"strings"
	"testing"
)

// TestDropsTotalHelpDeclaresEnforcementScope pins the #4508 clarification of
// the xpf_drops_total help text. The GlobalCtrDrops bridge (#4477) sums only
// the six ENFORCEMENT/admission reasons (policy deny, screen/IDS,
// host-inbound deny, source-NAT alloc fail, unknown VLAN, and destination-MAC
// admission reject) — it is NOT the literal total of every discarded packet
// (no-route/missing-neighbor, fabric-forwarding, VLAN-push, and NAT64
// fail-closed drops are excluded). The pre-#4508 help text was a bare "Total
// packets dropped." which misled an operator into reading the counter as the
// total discard count. This test fails RED if that regression is reverted, so
// the misleading "total" wording cannot silently return.
func TestDropsTotalHelpDeclaresEnforcementScope(t *testing.T) {
	c := newCollector(&Server{})
	// prometheus.Desc.String() embeds the help text verbatim, e.g.
	//   Desc{fqName: "xpf_drops_total", help: "...", ...}
	got := c.dropsTotal.String()

	// The clarified scope must name enforcement AND the primary excluded path.
	for _, want := range []string{"enforcement", "no-route", "undercounts"} {
		if !strings.Contains(got, want) {
			t.Errorf("xpf_drops_total help text is missing %q (the #4508 "+
				"enforcement-scope clarification) — got %q", want, got)
		}
	}

	// The misleading bare "Total packets dropped." wording must be gone: the
	// counter is enforcement-scoped, not a literal total of all discards.
	if strings.Contains(got, "Total packets dropped.") {
		t.Errorf("xpf_drops_total help text still carries the misleading "+
			"pre-#4508 %q wording — it undercounts total discards and must not "+
			"claim to be the total; got %q", "Total packets dropped.", got)
	}
}
