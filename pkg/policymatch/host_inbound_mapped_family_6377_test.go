package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// TestHostInboundMappedIPv6DstClassifiedAsV6 is the #6377 host-inbound
// fail-on-revert (Codex MINOR): hostInboundAdmission must classify the family of
// a mapped-IPv6 host-bound destination COLON-STRICTLY (ip6), not fold it to ip
// via To4(). The discriminator is a family-scoped system-service: `dhcpv6` is
// scoped to ip6 (config.HostInboundServiceFamily), so a mapped-v6 dst on udp/547
// admits ONLY when the classifier sees ip6. `dhcp` (ip, udp/67) is the v4 twin
// and proves the genuine-v4 path is intact.
//
// RED on revert: restore `family = ipFamily(q.DstIP)` in hostInboundAdmission.
// The mapped destination folds to ip, the ip6-scoped dhcpv6 token no longer
// matches, and the admission flips from TokenAdmit(dhcpv6) to Denied.
func TestHostInboundMappedIPv6DstClassifiedAsV6(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Zones:         hostZone("edge", []string{"dhcp", "dhcpv6"}, nil),
	}, config.ApplicationsConfig{})

	cases := []struct {
		name     string
		q        Query
		wantStat dpuserspace.HostInboundStatus
		wantTok  string
	}{
		{
			// The fix: a mapped-IPv6 destination is ip6, so the ip6-scoped
			// dhcpv6 token admits udp/547.
			name: "mapped-v6 dst udp/547 -> dhcpv6 (ip6) admits",
			q: Query{
				FromZone: "edge", ToZone: "junos-host", Protocol: "udp", DstPort: PortPtr(547),
				DstIP:     net.ParseIP("::ffff:192.0.2.1"),
				DstFamily: config.NATAddrFamily("::ffff:192.0.2.1"), // "v6"
			},
			wantStat: dpuserspace.HostInboundTokenAdmit, wantTok: "dhcpv6",
		},
		{
			// Control: a genuine v6 destination classifies the same way.
			name: "genuine v6 dst udp/547 -> dhcpv6 (ip6) admits",
			q: Query{
				FromZone: "edge", ToZone: "junos-host", Protocol: "udp", DstPort: PortPtr(547),
				DstIP:     net.ParseIP("2001:db8::1"),
				DstFamily: config.NATAddrFamily("2001:db8::1"), // "v6"
			},
			wantStat: dpuserspace.HostInboundTokenAdmit, wantTok: "dhcpv6",
		},
		{
			// Control: a genuine v4 destination is ip, so the ip-scoped dhcp
			// token admits udp/67 — the family threading did not break v4.
			name: "genuine v4 dst udp/67 -> dhcp (ip) admits",
			q: Query{
				FromZone: "edge", ToZone: "junos-host", Protocol: "udp", DstPort: PortPtr(67),
				DstIP:     net.ParseIP("10.0.0.1"),
				DstFamily: config.NATAddrFamily("10.0.0.1"), // "v4"
			},
			wantStat: dpuserspace.HostInboundTokenAdmit, wantTok: "dhcp",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// #16803: Match now returns the ingress-drop verdict for a
			// mapped destination (the frame never reaches the host gate),
			// so exercise the classifier directly — the ip6 classification
			// contract this test pins is unchanged.
			hi := hostInboundAdmission(cfg, c.q)
			if hi == nil {
				t.Fatalf("hostInboundAdmission == nil — host-inbound admission omitted")
			}
			if hi.Status != c.wantStat {
				t.Fatalf("status = %v, want %v (%+v)", hi.Status, c.wantStat, *hi)
			}
			if c.wantTok != "" && hi.Token != c.wantTok {
				t.Fatalf("token = %q, want %q (%+v)", hi.Token, c.wantTok, *hi)
			}
		})
	}

	// #16803: at the Match level the mapped-destination host-bound query
	// reports the ingress drop, not a host-inbound admission.
	res := Match(cfg, cases[0].q)
	if !res.V4MappedCompatIngressDrop || res.HostInbound != nil {
		t.Fatalf("mapped host-bound query must report the #10686 ingress drop (#16803), got %+v", res)
	}
}
