package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15207 A18-01 gRPC twin: predefined + predefined sets in list, shadowed label.

func TestShowApplicationsPredefined15207(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"junos-http": {Name: "junos-http", Protocol: "tcp", DestinationPort: "8080"},
	}
	var buf strings.Builder
	(&Server{}).showApplications(cfg, &buf)
	out := buf.String()
	if !strings.Contains(out, "junos-ssh") {
		t.Fatalf("gRPC list missing predefined apps:\n%s", out)
	}
	if !strings.Contains(out, "junos-sip") || !strings.Contains(out, "junos-sip-udp") {
		t.Fatalf("gRPC list missing predefined set junos-sip members:\n%s", out)
	}
	if !strings.Contains(out, "shadowed") {
		t.Fatalf("gRPC list must mark user junos-http as shadowing predefined:\n%s", out)
	}
	// filtered
	var buf2 strings.Builder
	(&Server{}).showApplicationsFiltered(cfg, &buf2, "junos-http")
	out2 := buf2.String()
	if !strings.Contains(out2, "8080") || !strings.Contains(out2, "shadowed") {
		t.Fatalf("gRPC filtered shadowed:\n%s", out2)
	}
	var buf3 strings.Builder
	(&Server{}).showApplicationsFiltered(cfg, &buf3, "junos-sip")
	if !strings.Contains(buf3.String(), "junos-sip-udp") {
		t.Fatalf("gRPC filtered set:\n%s", buf3.String())
	}
}
