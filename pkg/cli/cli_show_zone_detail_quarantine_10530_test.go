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
	// #12896 narrowed the ordinary control: a healthy zone never gains the
	// BLOCK qualifier, but a row whose peer zone is quarantined is per-row
	// qualified by the SSOT (what apply would scrub), so "no qualifier
	// anywhere" is no longer the contract.
	ordinary := captureStdout(t, func() {
		if err := c.showZonesDisplay(c.store.ActiveConfig(), true, "trust"); err != nil {
			t.Fatalf("showZonesDisplay ordinary: %v", err)
		}
	})
	ordinaryLines := strings.Split(ordinary, "\n")
	for i, line := range ordinaryLines {
		if strings.Contains(line, "Policy summary") {
			// The #10530 contract is about the dedicated block-qualifier LINE;
			// the references line above may legitimately carry per-reference
			// #12896 marks.
			if i == 0 || ordinaryLines[i-1] == "  "+config.ZoneQuarantinePoliciesQualifier {
				t.Fatalf("ordinary zones-detail gained the block qualifier:\n%s", ordinary)
			}
			break
		}
	}
	ordinaryRow := ""
	deadRow := ""
	for _, line := range ordinaryLines {
		if strings.Contains(line, "ordinary-rule") {
			ordinaryRow = line
		}
		if strings.Contains(line, "loser-rule") {
			deadRow = line
		}
	}
	if ordinaryRow == "" || deadRow == "" {
		t.Fatalf("ordinary zones-detail lost its policy rows:\n%s", ordinary)
	}
	if strings.Contains(ordinaryRow, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("live trust->trust row gained quarantine qualifier:\n%s", ordinaryRow)
	}
	if !strings.Contains(deadRow, config.ZoneQuarantinePoliciesQualifier) {
		t.Fatalf("peer-quarantined trust->z214 row lacks the #12896 scrub qualifier:\n%s", deadRow)
	}
}
