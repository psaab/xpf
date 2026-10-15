package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundStaleReplyGuardTextMultiScope13404(t *testing.T) {
	got := hostInboundStaleReplyGuardText([]xnft.StaleReplyGuardRule{{
		Family: "ip", Proto: config.HostInboundProtoTCP, Ports: []uint16{22},
		Addresses: []string{"192.0.2.1"},
		IngressVRFScopes: []config.HostInboundVRFIngressScope{
			{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}},
			{Master: "vrf-red", Slaves: []string{"ge-0-0-2"}},
		},
	}})
	if len(got) != 2 {
		t.Fatalf("rendered %d lines for one 2-scope guard, want 2 (one per scope): %v", len(got), got)
	}
	wantScopes := []string{
		"iifname \"vrf-blue\" meta sdifname \"ge-0-0-1\"",
		"iifname \"vrf-red\" meta sdifname \"ge-0-0-2\"",
	}
	for _, want := range wantScopes {
		found := false
		for _, line := range got {
			if strings.Contains(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("rendered lines %v do not contain single-scope predicate %q", got, want)
		}
	}
	for _, line := range got {
		if strings.Count(line, "iifname") != 1 {
			t.Errorf("rendered line contains %d iifname predicates, want exactly one: %s", strings.Count(line, "iifname"), line)
		}
	}
}
