package nftables

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundStaleReplyCatalogCoversAuthoritativeDiscreteTuples10752(t *testing.T) {
	exemptTCP := map[uint16]bool{20: true, 179: true, 512: true, 513: true, 514: true, 639: true, 646: true}
	exemptUDP := map[uint16]bool{67: true, 68: true, 123: true, 546: true, 547: true, 646: true}
	for _, family := range []string{"ip", "ip6"} {
		catalog := HostInboundStaleReplyCatalog(family)
		tcp, udp := portSet(catalog.TCP), portSet(catalog.UDP)
		if !sort.SliceIsSorted(catalog.TCP, func(i, j int) bool { return catalog.TCP[i] < catalog.TCP[j] }) ||
			!sort.SliceIsSorted(catalog.UDP, func(i, j int) bool { return catalog.UDP[i] < catalog.UDP[j] }) {
			t.Fatalf("%s catalog is not sorted: TCP=%v UDP=%v", family, catalog.TCP, catalog.UDP)
		}
		if len(tcp) != len(catalog.TCP) || len(udp) != len(catalog.UDP) {
			t.Fatalf("%s catalog contains duplicate ports: TCP=%v UDP=%v", family, catalog.TCP, catalog.UDP)
		}

		check := func(source string, matches []config.L4Match, tcpOnly bool) {
			t.Helper()
			for _, match := range matches {
				var got map[uint16]struct{}
				var exempt map[uint16]bool
				switch match.Proto {
				case config.HostInboundProtoTCP:
					got, exempt = tcp, exemptTCP
				case config.HostInboundProtoUDP:
					if tcpOnly {
						continue
					}
					got, exempt = udp, exemptUDP
				default:
					continue
				}
				for _, port := range match.Ports {
					if port.Lo != port.Hi || exempt[port.Lo] {
						continue
					}
					if _, ok := got[port.Lo]; !ok {
						t.Errorf("%s %s proto %d port %d missing from %s catalog", family, source, match.Proto, port.Lo, map[bool]string{true: "TCP", false: "UDP"}[match.Proto == config.HostInboundProtoTCP])
					}
				}
			}
		}
		for _, token := range config.HostInboundAllExpansionServices() {
			check("service "+token, config.HostInboundServiceMatch(token, family), false)
		}
		check("protocols all", config.HostInboundProtocolMatch("all", family), true)
		for _, match := range config.HostInboundProtocolMatch("all", family) {
			if match.Proto != config.HostInboundProtoUDP {
				continue
			}
			for _, port := range match.Ports {
				if port.Lo != port.Hi {
					continue
				}
				if _, ok := udp[port.Lo]; ok {
					t.Errorf("%s routing-protocol UDP port %d must remain outside the service stale-reply catalog", family, port.Lo)
				}
			}
		}

		for _, p := range []uint16{33434, 33523} {
			if _, ok := udp[p]; ok {
				t.Errorf("%s traceroute range endpoint %d must not be treated as a service source port", family, p)
			}
		}
		for _, p := range []uint16{67, 68, 123, 546, 547, 646} {
			if _, ok := udp[p]; ok {
				t.Errorf("%s client-role UDP port %d must remain outside the stale-reply catalog", family, p)
			}
		}
		for _, p := range []uint16{20, 179, 512, 513, 514, 639, 646} {
			if _, ok := tcp[p]; ok {
				t.Errorf("%s client-role TCP port %d must remain outside the stale-reply catalog", family, p)
			}
		}
	}
}

func TestHostInboundStaleReplyGuardRulesRespectAddressUnion10752(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "deny", SystemServices: []string{"snmp"}, V4Addrs: []string{"192.0.2.10"}},
		{Zone: "ike", SystemServices: []string{"ike"}, V4Addrs: []string{"192.0.2.11"}},
		{Zone: "open", SystemServices: []string{"any-service"}, V4Addrs: []string{"192.0.2.12"}},
	}
	rules := HostInboundStaleReplyGuardRules(views, []string{"192.0.2.13"}, nil, []uint16{51820})
	if !guardRuleHasTuple(rules, "192.0.2.10", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("IKE/UDP 500 reply to a denied covered address lacks a guard DROP")
	}
	if guardRuleHasTuple(rules, "192.0.2.11", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("still-admitted IKE/UDP 500 reply was guarded")
	}
	if guardRuleHasTuple(rules, "192.0.2.12", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("any-service address must not be covered by the stale-reply guard")
	}
	if !guardRuleHasTuple(rules, "192.0.2.13", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("addressed-but-unzoned address lacks the default-deny guard")
	}

	wgRules := HostInboundStaleReplyGuardRules(views[:1], nil, nil, []uint16{500})
	if guardRuleHasTuple(wgRules, "192.0.2.10", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("globally admitted WireGuard listen port was guarded")
	}
	sharedAddressRules := HostInboundStaleReplyGuardRules([]HostInboundZoneView{
		{Zone: "ssh", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.20"}},
		{Zone: "ike", SystemServices: []string{"ike"}, V4Addrs: []string{"192.0.2.20"}},
	}, nil, nil, nil)
	if guardRuleHasTuple(sharedAddressRules, "192.0.2.20", "ip", config.HostInboundProtoTCP, 22) ||
		guardRuleHasTuple(sharedAddressRules, "192.0.2.20", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("a service admitted by another view of the same address must not be guarded")
	}

	fenceRules := HostInboundStaleReplyFenceRules(views, []string{"192.0.2.13"}, nil, nil)
	if !guardRuleHasTuple(fenceRules, "192.0.2.11", "ip", config.HostInboundProtoUDP, 500) ||
		!guardRuleHasTuple(fenceRules, "192.0.2.12", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("cold-boot fence must guard service-port replies to every fenced address")
	}
}

func portSet(ports []uint16) map[uint16]struct{} {
	out := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		out[port] = struct{}{}
	}
	return out
}

func guardRuleHasTuple(rules []StaleReplyGuardRule, address, family string, proto uint8, port uint16) bool {
	for _, rule := range rules {
		if rule.Family != family || rule.Proto != proto {
			continue
		}
		foundAddr := false
		for _, addr := range rule.Addresses {
			if addr == address {
				foundAddr = true
				break
			}
		}
		if !foundAddr {
			continue
		}
		for _, got := range rule.Ports {
			if got == port {
				return true
			}
		}
	}
	return false
}
