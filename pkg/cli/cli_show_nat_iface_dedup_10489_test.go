package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestShowNATSourceSummaryDedupsInterfacePools10489(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{
			{Name: "r1", Then: config.NATThen{Interface: true}},
			{Name: "r2", Then: config.NATThen{Interface: true}},
		},
	}}
	out := captureStdout(t, func() {
		if err := (&CLI{}).showNATSourceSummary(cfg); err != nil {
			t.Fatalf("showNATSourceSummary: %v", err)
		}
	})
	if !strings.Contains(out, "Total pools: 1\n") {
		t.Fatalf("interface pools not deduped by zone pair, want Total pools 1:\n%s", out)
	}
	if got := strings.Count(out, "trust/untrust (interface)"); got != 1 {
		t.Fatalf("interface-pool rows = %d, want exactly 1:\n%s", got, out)
	}
}
