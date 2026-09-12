package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/psaab/xpf/pkg/config"
)

// netlink_scenario_test.go defines the CONSTRUCT-COMPLETE render matrix shared
// by the golden (T1b), kernel-load, and mutation-sensitivity tests. Every row of
// the plan §5.1 nft-text -> netlink mapping table is exercised at least once
// (§12.1): ct-state, ESP/AH, ICMP type sets + named accept counters, per-zone
// service accepts (tcp/udp dport, icmp echo-request), system-services all,
// protocols all, ident-reset (tcp-reset), empty default-deny zone, unzoned
// addrs, junos-host DENY (application-any, narrow-app, saddr, saddr!=,
// permit-subtract, IKE + ident shields), WireGuard port, dual-stack, named
// counters; and a full lo0 filter with host + CIDR interval sets, th port
// single/set/range/except, v4 + v6 (nibble-spanning) DSCP, icmp type+code,
// tcp-flags mask, ip frag + v6 exthdr frag, log, count, reject pair, discard,
// accept, fall-through.

func u8(v uint8) *uint8 { return &v }

// hostInboundScenario returns the construct-complete host-inbound spec.
func hostInboundScenario() HostInboundSpec {
	return HostInboundSpec{
		Views: []HostInboundZoneView{
			{
				// multi-service, dual-stack: tcp dport (ssh/https), icmp
				// echo-request (ping), udp dport set (dns), + catch-all drop.
				Zone:           "trust",
				SystemServices: []string{"ssh", "https", "ping", "dns"},
				V4Addrs:        []string{"10.0.1.1", "10.0.1.2"},
				V6Addrs:        []string{"2001:db8:1::1"},
			},
			{
				// #3226: `system-services all` is the named-service UNION, not
				// a full admit. It renders the same per-match rules any
				// explicit service list would (tcp/udp dport sets, icmp
				// echo-request, the ident-reset tcp/113 reject) and therefore
				// keeps its catch-all drop + deny counter. Before #3226 this
				// zone was the bare-accept/no-counter case — that construct
				// moved to the `admin` (any-service) view below, which is now
				// the ONLY full-admit token.
				Zone:           "mgmt",
				SystemServices: []string{"all"},
				V4Addrs:        []string{"10.0.9.1"},
			},
			{
				// system-services any-service -> bare accept, no drop/counter.
				// Keeps the full-admit construct covered after #3226 moved
				// `all` off it (dual-stack so both family arms are exercised).
				Zone:           "admin",
				SystemServices: []string{"any-service"},
				V4Addrs:        []string{"10.0.10.1"},
				V6Addrs:        []string{"2001:db8:10::1"},
			},
			{
				// protocols all -> routing-protocol set (meta l4proto, tcp, udp).
				Zone:      "core",
				Protocols: []string{"all"},
				V4Addrs:   []string{"10.0.5.1"},
				V6Addrs:   []string{"2001:db8:5::1"},
			},
			{
				// ident-reset -> reject with tcp reset.
				Zone:           "edge",
				SystemServices: []string{"ident-reset", "ssh"},
				V4Addrs:        []string{"10.0.7.1"},
			},
			{
				// empty stanza -> default-deny (only the catch-all drop).
				Zone:    "quarantine",
				V4Addrs: []string{"10.0.8.1"},
				V6Addrs: []string{"2001:db8:8::1"},
			},
		},
		UnzonedV4:     []string{"10.0.99.1"},
		UnzonedV6:     []string{"2001:db8:99::1"},
		WGListenPorts: []uint16{51820, 51821},
		Programs: []JunosHostProgram{
			{
				Zone:                  "untrust",
				IngressIfnames:        []string{"ge-0-0-2", "ge-0-0-2.50"},
				HasApplicationAnyDeny: true,
				CoarseAdmitsIKE:       true,
				CoarseIdentResets:     true,
				IKEExemptNetdevs:      []string{"ge-0-0-2"},
				IdentResetNetdevs:     []string{"ge-0-0-2"},
				RulesV4: []JunosHostDenyRule{
					{
						// #9504: an earlier permit's carve, rendered as a return.
						Family:  "ip",
						Src:     []string{"192.0.2.10"},
						Verdict: config.JunosHostReturn,
					},
					{
						// application any, positive saddr set.
						Family: "ip",
						Src:    []string{"192.0.2.0/24", "198.51.100.7"},
					},
					{
						// narrow-app tcp dport, source-excluded saddr.
						Family:      "ip",
						SrcExcluded: true,
						Src:         []string{"203.0.113.0/24"},
						L4:          []JunosHostDenyL4{{Proto: config.HostInboundProtoTCP, Ports: []PortRange{{22, 22}}}},
					},
					{
						// icmp type+code, any source.
						Family: "ip",
						SrcAny: true,
						L4:     []JunosHostDenyL4{{Proto: config.HostInboundProtoICMP, ICMPType: u8(8), ICMPCode: u8(0)}},
					},
				},
				RulesV6: []JunosHostDenyRule{
					{
						// bare proto (GRE) v6, source set.
						Family: "ip6",
						Src:    []string{"2001:db8:a::/48"},
						L4:     []JunosHostDenyL4{{Proto: 47}},
					},
				},
			},
		},
	}
}

// lo0Scenario returns the construct-complete lo0 filter spec.
func lo0Scenario() Lo0FilterSpec {
	return Lo0FilterSpec{
		V4Terms: []Lo0FilterTerm{
			{
				// host saddr + CIDR daddr interval set, tcp dport single, count.
				Name:             "ssh-in",
				SrcConstrained:   true,
				SrcAddrs:         []string{"10.0.0.0/8"},
				DstConstrained:   true,
				DstAddrs:         []string{"10.0.1.1"},
				Protocols:        []string{"tcp"},
				DestinationPorts: []string{"22"},
				Count:            "ssh_hits",
				Action:           "accept",
			},
			{
				// th sport set + th dport range + dscp v4 + log, discard.
				Name:             "range-drop",
				SourcePorts:      []string{"1024", "2048"},
				DestinationPorts: []string{"33434-33523"},
				DSCPs:            []string{"ef"},
				Log:              true,
				Action:           "discard",
			},
			{
				// dport-except + icmp type+code + frag, reject (pair).
				Name:            "reject-term",
				DestPortsExcept: []string{"80", "443"},
				ICMPTypes:       []int{3},
				ICMPCodes:       []int{4},
				IsFragment:      true,
				Action:          "reject",
			},
			{
				// tcp-flags mask, accept.
				Name:     "syn-only",
				TCPFlags: []string{"syn", "&", "!ack"},
				Action:   "accept",
			},
			{
				// modifier-only fall-through (count, no verdict).
				Name:   "count-only",
				Count:  "audit",
				Action: "",
			},
			{
				// multi-host daddr exact set + protocol set, accept.
				Name:           "multi",
				DstConstrained: true,
				DstAddrs:       []string{"10.0.1.1", "10.0.1.2"},
				Protocols:      []string{"tcp", "udp"},
				Action:         "accept",
			},
		},
		V6Terms: []Lo0FilterTerm{
			{
				// v6 dscp (nibble-spanning), daddr CIDR interval, accept.
				Name:           "v6-dscp",
				DstConstrained: true,
				DstAddrs:       []string{"2001:db8::/32"},
				DSCPs:          []string{"cs1"},
				Action:         "accept",
			},
			{
				// v6 exthdr frag + icmpv6 type set, discard.
				Name:       "v6-frag",
				ICMPTypes:  []int{1, 2},
				IsFragment: true,
				Action:     "discard",
			},
			{
				// saddr except set, th dport != set, accept.
				Name:            "v6-except",
				SrcConstrained:  true,
				SrcExcept:       true,
				SrcAddrs:        []string{"2001:db8:bad::/48"},
				DestPortsExcept: []string{"22"},
				Action:          "accept",
			},
		},
	}
}

func fenceScenario() FenceSpec {
	hi := hostInboundScenario()
	return FenceSpec{
		Views:         hi.Views,
		UnzonedV4:     hi.UnzonedV4,
		UnzonedV6:     hi.UnzonedV6,
		WGListenPorts: hi.WGListenPorts,
	}
}

func gapFenceScenario() GapFenceSpec {
	return GapFenceSpec{
		UncoveredV4:   []string{"10.0.1.1", "10.0.9.1"},
		UncoveredV6:   []string{"2001:db8:1::1"},
		WGListenPorts: []uint16{51820},
	}
}

// newBuildPlan constructs an nlPlan bound to a fresh (unflushed) netlink batch
// with an inet table + `input` chain, for pure-unit rule inspection. It skips
// the test if a netlink socket cannot be opened.
func newBuildPlan(t *testing.T, tableName string, prio nftables.ChainPriority) *nlPlan {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Skipf("nftables.New unavailable (%v)", err)
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: tableName})
	p := prio
	pol := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &p,
		Policy:   &pol,
	})
	return &nlPlan{c: c, table: tbl, chain: ch}
}
