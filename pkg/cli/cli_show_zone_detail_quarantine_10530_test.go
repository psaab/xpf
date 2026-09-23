package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestZoneDetailCallerPrefixContract10530(t *testing.T) {
	c := quarantinePolicyCLI10530(t)
	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), true, "z214"); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	if !strings.Contains(out, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("zones-detail quarantined policy block lacks caller qualifier:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	summaryAdjacent := false
	for i, line := range lines {
		if strings.Contains(line, "Policy summary") {
			if i == 0 || !strings.Contains(lines[i-1], config.ZoneQuarantinePoliciesQualifier) {
				t.Fatalf("caller qualifier is not immediately adjacent to SSOT summary:\n%s", out)
			}
			summaryAdjacent = true
			break
		}
	}
	if !summaryAdjacent {
		t.Fatalf("zones-detail omitted shared policy summary:\n%s", out)
	}
	ordinary := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), true, "trust"); err != nil {
			t.Fatalf("showZonesDisplay ordinary: %v", err)
		}
	})
	if strings.Contains(ordinary, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("ordinary zones-detail gained quarantine qualifier:\n%s", ordinary)
	}
}
