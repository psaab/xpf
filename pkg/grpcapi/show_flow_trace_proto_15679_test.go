package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15679: gRPC show security flow traceoptions must render proto=.
func TestShowFlowTraceoptionsProto15679(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.Traceoptions = &config.FlowTraceoptions{
		File: "rt.log",
		PacketFilters: []*config.TracePacketFilter{
			{Name: "pf1", Protocol: "47", SourcePrefix: "10.0.0.0/8"},
		},
	}
	var buf strings.Builder
	(&Server{}).showFlowTraceoptions(cfg, &buf)
	if !strings.Contains(buf.String(), "proto=47") {
		t.Fatalf("gRPC show missing proto=47:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "src=10.0.0.0/8") {
		t.Fatalf("gRPC show missing src:\n%s", buf.String())
	}
}
