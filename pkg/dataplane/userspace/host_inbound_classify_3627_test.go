package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func u8ptr(v uint8) *uint8 { return &v }

func cfgWithHostInbound(zone string, svc, proto []string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		zone: {
			Name:               zone,
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: svc, Protocols: proto},
		},
	}
	return cfg
}

// TestClassifyHostInboundReportsAdmittingToken is the #3627 B1a classifier
// guard: given the ingress zone's host-inbound-traffic set and a host-bound
// query tuple, ClassifyHostInbound reports the admitting system-service /
// protocol token (or deny / global-accept / indeterminate). It reads the SAME
// structured SSOT the nft builder renders from, so a reported token cannot claim
// a port the kernel does not open.
func TestClassifyHostInboundReportsAdmittingToken(t *testing.T) {
	const TCP, UDP = uint8(6), uint8(17)
	const ICMP, ICMPv6 = uint8(1), uint8(58)
	const ESP = uint8(50)

	// Zone admits ssh + ping (system-services) and bgp (protocols).
	cfg := cfgWithHostInbound("edge", []string{"ssh", "ping"}, []string{"bgp"})

	cases := []struct {
		name     string
		proto    uint8
		hasProto bool
		dstPort  int
		icmpType *uint8
		family   string
		want     HostInboundStatus
		wantTok  string
		wantKind string
	}{
		{"ssh tcp/22 admits", TCP, true, 22, nil, "ip", HostInboundTokenAdmit, "ssh", "system-services"},
		{"ssh v6 admits (dual)", TCP, true, 22, nil, "ip6", HostInboundTokenAdmit, "ssh", "system-services"},
		{"telnet tcp/23 denied", TCP, true, 23, nil, "ip", HostInboundDenied, "", ""},
		{"bgp tcp/179 admits (protocols)", TCP, true, 179, nil, "ip", HostInboundTokenAdmit, "bgp", "protocols"},
		{"ping v4 echo admits", ICMP, true, 0, u8ptr(8), "ip", HostInboundTokenAdmit, "ping", "system-services"},
		{"ping v6 echo admits", ICMPv6, true, 0, u8ptr(128), "ip6", HostInboundTokenAdmit, "ping", "system-services"},
		{"icmp error global-accept", ICMP, true, 0, u8ptr(3), "ip", HostInboundGlobalAccept, "", ""},
		{"v6 ND global-accept", ICMPv6, true, 0, u8ptr(135), "ip6", HostInboundGlobalAccept, "", ""},
		{"esp global-accept", ESP, true, 0, nil, "ip", HostInboundGlobalAccept, "", ""},
		{"tcp no port -> indeterminate", TCP, true, 0, nil, "ip", HostInboundIndeterminate, "", ""},
		{"no protocol -> indeterminate", 0, false, 0, nil, "ip", HostInboundIndeterminate, "", ""},
		{"udp/53 denied (dns not admitted)", UDP, true, 53, nil, "ip", HostInboundDenied, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyHostInbound(cfg, "edge", c.proto, c.hasProto, c.dstPort, c.icmpType, c.family)
			if got.Status != c.want {
				t.Fatalf("status = %v, want %v (%+v)", got.Status, c.want, got)
			}
			if got.Token != c.wantTok || got.Kind != c.wantKind {
				t.Fatalf("token/kind = %q/%q, want %q/%q", got.Token, got.Kind, c.wantTok, c.wantKind)
			}
		})
	}
}

// TestClassifyHostInboundFullAdmit: `system-services all` admits every tuple,
// even one that is otherwise indeterminate (no port).
func TestClassifyHostInboundFullAdmit(t *testing.T) {
	// #3226: `any-service` is the packet-wide full admit. It reports a
	// token-admit for ANY tuple — here a TCP query with no port, which no
	// per-service match could satisfy.
	cfg := cfgWithHostInbound("edge", []string{"any-service"}, nil)
	got := ClassifyHostInbound(cfg, "edge", 6, true, 0, nil, "ip")
	if got.Status != HostInboundTokenAdmit || got.Token != "any-service" {
		t.Fatalf("full-admit: got %+v, want token-admit any-service", got)
	}
	// `all` is NOT a full admit any more: it expands to the named-service
	// union, so an unlisted port is DENIED and a raw IP protocol is DENIED.
	// Restoring `all` to config.HostInboundFullAdmitService turns both RED
	// (the full-admit branch reports token-admit before the tuple is examined).
	scoped := cfgWithHostInbound("edge", []string{"all"}, nil)
	if got := ClassifyHostInbound(scoped, "edge", 6, true, 9999, nil, "ip"); got.Status != HostInboundDenied {
		t.Fatalf("system-services all tcp/9999: got %+v, want denied (#3226 — `all` is not a full admit)", got)
	}
	if got := ClassifyHostInbound(scoped, "edge", 89, true, 0, nil, "ip"); got.Status != HostInboundDenied {
		t.Fatalf("system-services all ospf/proto-89: got %+v, want denied (#3226 — `all` is not a full admit)", got)
	}
}

// TestClassifyHostInboundIdentResetDenies: a zone whose only service is
// ident-reset does NOT admit tcp/113 — the Reject marker keeps the classifier
// from reporting ident-reset as admitting (Junos resets, does not permit).
func TestClassifyHostInboundIdentResetDenies(t *testing.T) {
	cfg := cfgWithHostInbound("edge", []string{"ident-reset"}, nil)
	got := ClassifyHostInbound(cfg, "edge", 6, true, 113, nil, "ip")
	if got.Status != HostInboundDenied {
		t.Fatalf("ident-reset tcp/113: got %+v, want denied (ident-reset resets, does not admit)", got)
	}
}

// TestClassifyHostInboundNoStanzaDenies: a configured zone with no
// host-inbound-traffic stanza default-denies every service (post-#3405), so a
// host-bound ssh query is DENIED, not admitted.
func TestClassifyHostInboundNoStanzaDenies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{"edge": {Name: "edge"}}
	got := ClassifyHostInbound(cfg, "edge", 6, true, 22, nil, "ip")
	if got.Status != HostInboundDenied {
		t.Fatalf("no-stanza zone ssh: got %+v, want denied (#3405 default-deny)", got)
	}
}

// TestClassifyHostInboundFamilyGate: dhcp is IPv4-only; a v6 dhcp query is not
// admitted by an dhcp-only zone.
func TestClassifyHostInboundFamilyGate(t *testing.T) {
	cfg := cfgWithHostInbound("edge", []string{"dhcp"}, nil)
	if got := ClassifyHostInbound(cfg, "edge", 17, true, 67, nil, "ip"); got.Status != HostInboundTokenAdmit || got.Token != "dhcp" {
		t.Fatalf("dhcp v4 udp/67: got %+v, want token-admit dhcp", got)
	}
	if got := ClassifyHostInbound(cfg, "edge", 17, true, 67, nil, "ip6"); got.Status != HostInboundDenied {
		t.Fatalf("dhcp v6 udp/67: got %+v, want denied (dhcp is IPv4-only)", got)
	}
}

// #15671: ND is token-admitted by ndp, default-admitted without an
// ndp exclusion, and denied when ndp was excepted.
func TestClassifyHostInboundNDP15671(t *testing.T) {
	const ICMPv6 = uint8(58)
	ndpCfg := cfgWithHostInbound("edge", nil, []string{"ndp"})
	if got := ClassifyHostInbound(ndpCfg, "edge", ICMPv6, true, 0, u8ptr(135), "ip6"); got.Status != HostInboundTokenAdmit || got.Token != "ndp" {
		t.Fatalf("ndp zone NS: got %+v, want token-admit ndp", got)
	}
	plain := cfgWithHostInbound("edge", nil, []string{"ospf"})
	if got := ClassifyHostInbound(plain, "edge", ICMPv6, true, 0, u8ptr(135), "ip6"); got.Status != HostInboundGlobalAccept {
		t.Fatalf("plain zone NS: got %+v, want global-accept (ND default)", got)
	}
}
