package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	ddnspkg "github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15700: gRPC twins of the CLI defects — v6 DHCP DDNS ignored, orphan
// alarm/counter omitted, blank update-server= for HTTP backends.

func TestShowDHCPDynamicDNS_V6Only_15700(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DHCPServer.DynamicDNSv6 = &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "v6.example.com", Backend: "rfc2136", UpdateServer: "2001:db8::53"}
	s := &Server{ddnsStatsFn: func() *dhcpserver.DDNSStats { return &dhcpserver.DDNSStats{OwnedRecords: 2} }}
	var buf strings.Builder
	s.showDHCPDynamicDNS(cfg, &buf, false)
	out := buf.String()
	if strings.Contains(out, "not configured") {
		t.Fatalf("v6-only must not print not-configured:\n%s", out)
	}
	if !strings.Contains(out, "v6.example.com") || !strings.Contains(out, "IPv6") || !strings.Contains(out, "Owned records: 2") {
		t.Fatalf("v6 section + counters missing:\n%s", out)
	}
}

func TestShowServicesDynamicDNS_OrphanAndTargets_15700(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Services = &config.SystemServicesConfig{DynamicDNS: &config.DDNSServicesConfig{Providers: map[string]*config.DDNSProvider{
		"cf":  {Name: "cf", Backend: "cloudflare", Zone: "example.net"},
		"aws": {Name: "aws", Backend: "route53", HostedZoneID: "Z123"},
		"gen": {Name: "gen", Backend: "generic", URLTemplate: "https://user:pw@dns.example/upd?token=SECRET"},
		"dyn": {Name: "dyn", Backend: "dyndns2", Server: "https://dyn.example/nic/update"},
	}}}
	s := &Server{surfaceADDNSStatsFn: func() *ddnspkg.SurfaceAStats { return &ddnspkg.SurfaceAStats{Scopes: 1, Orphaned: 2} }}
	var buf strings.Builder
	s.showServicesDynamicDNS(cfg, &buf, false)
	out := buf.String()
	if !strings.Contains(out, "ALARM") || !strings.Contains(out, "2 record(s) orphaned") {
		t.Errorf("gRPC must alarm on orphaned records in summary:\n%s", out)
	}
	if !strings.Contains(out, "Orphaned records:  2") {
		t.Errorf("gRPC counters must include orphaned count:\n%s", out)
	}
	for _, want := range []string{"zone=example.net", "hosted-zone-id=Z123", "server=https://dyn.example/nic/update", "url-template=https://<redacted>@dns.example/upd?<redacted>"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "update-server=") || strings.Contains(out, "pw@") {
		t.Errorf("blank update-server or credential leak:\n%s", out)
	}
}
