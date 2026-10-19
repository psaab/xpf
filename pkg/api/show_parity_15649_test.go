package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15649 parity (REST leg): same SSOT output for timeouts, IPFIX monitoring,
// expanded application-set members.

func TestRESTFlowTimeoutsSSOT15649(t *testing.T) {
	s := stageShowTextConfig(t, []string{"set security zones security-zone trust", "set security flow gre-performance-acceleration"})
	out := renderShowTextBody(t, s, "flow-timeouts")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "ICMP") && strings.Contains(l, "30s") {
			t.Errorf("ICMP 30s: %q", l)
		}
	}
	if !strings.Contains(out, "60s (default)") || strings.Contains(out, "#5804") {
		t.Errorf("REST timeouts divergent:\n%s", out)
	}
}

func TestRESTFlowMonitoringIPFIXOnly15649(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{VersionIPFIX: &config.NetFlowIPFIXConfig{Templates: map[string]*config.NetFlowIPFIXTemplate{
		"ipfix1": {Name: "ipfix1"},
	}}}
	var sb strings.Builder
	config.RenderFlowMonitoring(&sb, cfg, nil)
	if strings.Contains(sb.String(), "No flow monitoring configured") {
		t.Fatalf("IPFIX-only unconfigured")
	}
}

func TestRESTApplicationsExpanded15649(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set applications application multi term t1 protocol tcp destination-port 8443",
		"set applications application-set my-set application multi",
		"set applications application-set outer-set application-set my-set",
	})
	out := renderShowTextBody(t, s, "applications")
	if !strings.Contains(out, "multi-t1") {
		t.Errorf("expanded term member missing (want multi-t1 in outer-set):\n%s", out)
	}
}
