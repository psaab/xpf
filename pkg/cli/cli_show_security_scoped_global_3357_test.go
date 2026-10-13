package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3357: the FILTERED local-CLI policy views (`show security policies
// hit-count from-zone X to-zone Y`, `... detail ...`) suppressed the global
// block entirely (`fromZone == "" && toZone == ""` gate). A scoped global
// (#3148) `match from-zone X to-zone Y` that is actively enforced for that
// exact pair was therefore omitted from the very command an operator uses to
// prove which rules govern the pair. The filtered views now include an
// unscoped global (every transit pair) and a scoped global targeting the
// filter, and exclude a scoped global bound to a different pair.

// scopedGlobalCLIConfig3357 has a scoped global for trust->untrust, a scoped
// global for the off-pair trust->dmz, and an unscoped (all-zones) global.
func scopedGlobalCLIConfig3357() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {}, "untrust": {}, "dmz": {},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{
			Name:   "scoped-tu",
			Match:  config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"untrust"}},
			Action: config.PolicyDeny,
		},
		{
			Name:   "scoped-td",
			Match:  config.PolicyMatch{FromZones: []string{"trust"}, ToZones: []string{"dmz"}},
			Action: config.PolicyDeny,
		},
		{
			Name:   "open-global",
			Action: config.PolicyPermit,
		},
	}
	return cfg
}

// Test_3357_PolicyHitCountFilteredShowsScopedGlobal covers the hit-count table.
// FAIL-ON-REVERT: restoring the `fromZone == "" && toZone == ""` gate suppresses
// the global block, so the scoped-tu / open-global assertions go RED.
func Test_3357_PolicyHitCountFilteredShowsScopedGlobal(t *testing.T) {
	cfg := scopedGlobalCLIConfig3357()
	c := &CLI{
		// hit-count returns early unless a dataplane is loaded.
		dp: &policyCounterCLIDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "trust", "untrust"); err != nil {
			t.Fatalf("showPoliciesHitCount: %v", err)
		}
	})

	scoped := briefRow(t, out, "scoped-tu")
	if !(strings.Contains(scoped, "trust") && strings.Contains(scoped, "untrust")) {
		t.Fatalf("scoped-tu hit-count row = %q, want trust/untrust columns "+
			"(filtered view suppressed the scoped global — #3357 regression)", scoped)
	}
	open := briefRow(t, out, "open-global")
	if !strings.Contains(open, "junos-global") {
		t.Fatalf("open-global hit-count row = %q, want junos-global columns (unscoped global)", open)
	}
	if strings.Contains(out, "scoped-td") {
		t.Fatalf("filtered hit-count leaked an off-pair scoped global (trust->dmz):\n%s", out)
	}
}

// Test_3357_PolicyDetailFilteredShowsScopedGlobal covers the detail view.
// FAIL-ON-REVERT: restoring the gate suppresses the global block, so the
// scoped-tu zone-line assertion goes RED.
func Test_3357_PolicyDetailFilteredShowsScopedGlobal(t *testing.T) {
	cfg := scopedGlobalCLIConfig3357()
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "trust", "untrust"); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	scoped := policyDetailZoneLine(t, out, "scoped-tu")
	if !strings.Contains(scoped, "From zone: trust") || !strings.Contains(scoped, "To zone: untrust") {
		t.Fatalf("scoped-tu detail zone line = %q, want From zone: trust / To zone: untrust "+
			"(filtered view suppressed the scoped global — #3357 regression)", scoped)
	}
	if !strings.Contains(out, "Policy: open-global") {
		t.Fatalf("filtered detail dropped the unscoped (all-zones) global:\n%s", out)
	}
	if strings.Contains(out, "scoped-td") {
		t.Fatalf("filtered detail leaked an off-pair scoped global (trust->dmz):\n%s", out)
	}
}
