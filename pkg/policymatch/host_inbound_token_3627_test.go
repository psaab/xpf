package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// hostZone builds a zone map with one zone carrying a host-inbound-traffic set,
// for the #3627 B1a host-inbound token-report tests.
func hostZone(name string, svc, proto []string) map[string]*config.ZoneConfig {
	return map[string]*config.ZoneConfig{
		name: {
			Name:               name,
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: svc, Protocols: proto},
		},
	}
}

// TestMatchReportsHostInboundAdmittingToken is the #3627 B1a RED-on-revert guard
// at the simulator level: a `to-zone junos-host` query with no matching
// host-bound policy returns HostInboundUnmatched AND carries a HostInbound
// admission naming the host-inbound-traffic token that admits the tuple (or
// deny / global-accept / indeterminate). Before B1a the host-inbound response
// omitted the admitting token entirely (res.HostInbound == nil).
func TestMatchReportsHostInboundAdmittingToken(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         hostZone("edge", []string{"ssh", "ping"}, []string{"bgp"}),
	}, config.ApplicationsConfig{})

	cases := []struct {
		name     string
		q        Query
		wantStat dpuserspace.HostInboundStatus
		wantTok  string
		wantKind string
	}{
		{
			name:     "ssh admits -> names the ssh system-service",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(22), DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundTokenAdmit, wantTok: "ssh", wantKind: "system-services",
		},
		{
			name:     "bgp admits -> names the bgp protocol",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(179), DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundTokenAdmit, wantTok: "bgp", wantKind: "protocols",
		},
		{
			name:     "telnet denied -> host-inbound default-deny",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(23), DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundDenied,
		},
		{
			name:     "icmp error -> global accept",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "icmp", ICMPType: u8(3), DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundGlobalAccept,
		},
		{
			name:     "no protocol -> indeterminate",
			q:        Query{FromZone: "edge", ToZone: "junos-host", DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundIndeterminate,
		},
		{
			// #17081: a PRESENT literal dst port 0 is decided, not
			// indeterminate - no host-inbound token admits port 0.
			name:     "literal dst port 0 -> denied, not indeterminate",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "tcp", DstPort: PortPtr(0), DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundDenied,
		},
		{
			name:     "omitted dst port -> indeterminate (control)",
			q:        Query{FromZone: "edge", ToZone: "junos-host", Protocol: "tcp", DstIP: net.ParseIP("192.0.2.1")},
			wantStat: dpuserspace.HostInboundIndeterminate,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Match(cfg, c.q)
			if !res.HostInboundUnmatched {
				t.Fatalf("HostInboundUnmatched = false, want true")
			}
			if res.HostInbound == nil {
				t.Fatalf("res.HostInbound == nil — host-inbound admitting token omitted (#3627 B1a regression)")
			}
			if res.HostInbound.Status != c.wantStat {
				t.Fatalf("status = %v, want %v (%+v)", res.HostInbound.Status, c.wantStat, *res.HostInbound)
			}
			if res.HostInbound.Token != c.wantTok || res.HostInbound.Kind != c.wantKind {
				t.Fatalf("token/kind = %q/%q, want %q/%q", res.HostInbound.Token, res.HostInbound.Kind, c.wantTok, c.wantKind)
			}
			if c.wantStat == dpuserspace.HostInboundTokenAdmit && res.HostInbound.Describe() == "" {
				t.Errorf("token-admit must render a non-empty Describe() line")
			}
		})
	}
}

// TestMatchHostInboundOnlyOnHostPath: the HostInbound field is set only on the
// host path — a transit query never carries it.
func TestMatchHostInboundOnlyOnHostPath(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyPermit,
		Zones:         hostZone("edge", []string{"ssh"}, nil),
	}, config.ApplicationsConfig{})
	// Add a second zone so a transit pair exists.
	cfg.Security.Zones["core"] = &config.ZoneConfig{Name: "core"}

	res := Match(cfg, Query{FromZone: "edge", ToZone: "core", Protocol: "tcp", DstPort: PortPtr(22)})
	if res.HostInbound != nil {
		t.Errorf("transit query carried a HostInbound admission (%+v); it must be host-path only", *res.HostInbound)
	}
}
