package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15649 parity (gRPC leg): flow timeouts SSOT, IPFIX-only monitoring,
// GRE #7188 wording (supersedes stale #5804 assertions).

func TestGRPCFlowTimeoutsSSOT15649(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.GREPerformanceAcceleration = true
	var buf strings.Builder
	(&Server{}).showFlowTimeouts(cfg, &buf)
	out := buf.String()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "ICMP") && (strings.Contains(l, "30s") || strings.Contains(l, " 0s")) {
			t.Errorf("ICMP divergent: %q", l)
		}
	}
	if !strings.Contains(out, "60s (default)") || !strings.Contains(out, "1800s (default)") {
		t.Errorf("missing defaults:\n%s", out)
	}
	if strings.Contains(out, "#5804") || strings.Contains(out, "remain 5-tuple") {
		t.Errorf("stale GRE:\n%s", out)
	}
	if !strings.Contains(out, "#7188") {
		t.Errorf("missing #7188 GRE wording:\n%s", out)
	}
}

func TestGRPCFlowMonitoringIPFIXOnly15649(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{VersionIPFIX: &config.NetFlowIPFIXConfig{Templates: map[string]*config.NetFlowIPFIXTemplate{
		"ipfix1": {Name: "ipfix1", FlowActiveTimeout: 60},
	}}}
	var buf strings.Builder
	(&Server{}).showFlowMonitoring(cfg, &buf)
	if strings.Contains(buf.String(), "No flow monitoring configured") {
		t.Fatalf("IPFIX-only as unconfigured:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "ipfix1") {
		t.Errorf("missing template:\n%s", buf.String())
	}
}

func TestGRPCForwardingIPFIXBinding15649(t *testing.T) {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{Instances: map[string]*config.SamplingInstance{
		"s1": {Name: "s1", FamilyInet: &config.SamplingFamily{InlineJflow: true, InlineJflowSourceAddress: "10.0.0.1", FlowServers: []*config.FlowServer{{Address: "192.0.2.1", Port: 4739, VersionIPFIXTemplate: "ipfix1"}}}},
	}}
	var buf strings.Builder
	(&Server{}).showForwardingOptions(cfg, &buf)
	out := buf.String()
	if !strings.Contains(out, "IPFIX template: ipfix1") {
		t.Errorf("missing IPFIX binding:\n%s", out)
	}
	if !strings.Contains(out, "Inline jflow source: 10.0.0.1") {
		t.Errorf("missing inline-jflow source:\n%s", out)
	}
}
