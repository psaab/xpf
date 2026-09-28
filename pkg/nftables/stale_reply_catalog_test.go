package nftables

import (
	"bytes"
	"sort"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/psaab/xpf/pkg/config"
)

func TestHostInboundStaleReplyIsExemptMatchesTokens10752(t *testing.T) {
	for _, tok := range []string{"dhcp", "bootp", "dhcpv6", "ntp"} {
		for _, family := range []string{"ip", "ip6"} {
			for _, m := range config.HostInboundServiceMatch(tok, family) {
				for _, p := range m.Ports {
					if p.Lo != p.Hi {
						continue
					}
					if !HostInboundStaleReplyIsExempt(m.Proto, p.Lo) {
						t.Errorf("exempt token %s port %d must be IsExempt", tok, p.Lo)
					}
				}
			}
		}
	}
	for _, tcp := range []uint16{20, 179, 512, 513, 514, 639, 646} {
		if !HostInboundStaleReplyIsExempt(config.HostInboundProtoTCP, tcp) {
			t.Errorf("TCP exempt port %d must be IsExempt", tcp)
		}
	}
	if !HostInboundStaleReplyIsExempt(config.HostInboundProtoUDP, 646) {
		t.Error("UDP 646 must be IsExempt")
	}
	for _, tc := range []struct {
		proto uint8
		port  uint16
	}{
		{config.HostInboundProtoTCP, 22},
		{config.HostInboundProtoTCP, 2222},
		{config.HostInboundProtoUDP, 161},
		{config.HostInboundProtoUDP, 500},
	} {
		if HostInboundStaleReplyIsExempt(tc.proto, tc.port) {
			t.Errorf("non-exempt %d/%d must not be IsExempt", tc.proto, tc.port)
		}
	}
}

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
	rules := HostInboundStaleReplyGuardRules(views, []string{"192.0.2.13"}, nil, []uint16{51820}, false)
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

	wgRules := HostInboundStaleReplyGuardRules(views[:1], nil, nil, []uint16{500}, false)
	if guardRuleHasTuple(wgRules, "192.0.2.10", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("globally admitted WireGuard listen port was guarded")
	}
	sharedAddressRules := HostInboundStaleReplyGuardRules([]HostInboundZoneView{
		{Zone: "ssh", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.20"}},
		{Zone: "ike", SystemServices: []string{"ike"}, V4Addrs: []string{"192.0.2.20"}},
	}, nil, nil, nil, false)
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

func TestHostInboundStaleReplyGuardsFollowIngressPolicy10752(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "deny", SystemServices: []string{"snmp"}, V4Addrs: []string{"192.0.2.10"}, IngressNetdevs: []string{"eth-deny"}},
		{Zone: "open", SystemServices: []string{"any-service"}, V4Addrs: []string{"192.0.2.12"}, IngressNetdevs: []string{"eth-open"}},
	}
	rules := HostInboundStaleReplyGuardRules(views, nil, nil, nil, true)
	// Denying ingress emits a positive iifname guard covering every judged
	// destination, including the open zone's address.
	if !guardRuleHasIngressTuple(rules, []string{"eth-deny"}, false, "192.0.2.12", "ip", config.HostInboundProtoTCP, 22) {
		t.Fatal("denying ingress must guard TCP/22 to every judged destination including 192.0.2.12")
	}
	if !guardRuleHasIngressTuple(rules, []string{"eth-deny"}, false, "192.0.2.10", "ip", config.HostInboundProtoUDP, 500) {
		t.Fatal("denying ingress must guard UDP/500")
	}
	// Open ingress emits no per-ingress guard.
	for _, r := range rules {
		if !r.IngressNegated && len(r.Ingress) == 1 && r.Ingress[0] == "eth-open" {
			t.Fatalf("open ingress must emit no per-ingress guard, got %+v", r)
		}
	}
	// Fallback is negated, covers the owner-denied address, omits the open
	// address, and excludes the trusted reinject TUN.
	foundFallback := false
	for _, r := range rules {
		if !r.IngressNegated {
			continue
		}
		hasReinject := false
		for _, n := range r.Ingress {
			if n == HostInboundReinjectIfname {
				hasReinject = true
			}
		}
		if !hasReinject {
			t.Fatalf("fallback must exclude trusted reinject TUN, got %+v", r)
		}
		for _, a := range r.Addresses {
			if a == "192.0.2.12" {
				t.Fatalf("open address must not appear in fallback: %+v", r)
			}
			if a == "192.0.2.10" && r.Proto == config.HostInboundProtoTCP {
				for _, p := range r.Ports {
					if p == 22 {
						foundFallback = true
					}
				}
			}
		}
	}
	if !foundFallback {
		t.Fatal("owner-denied address must retain negated fallback for TCP/22")
	}
	// Fence guards stay destination-only.
	for _, r := range HostInboundStaleReplyFenceRules(views, nil, nil, nil) {
		if len(r.Ingress) != 0 || r.IngressNegated {
			t.Fatalf("fence guard must be destination-only, got %+v", r)
		}
	}
	// Stale (no trusted reinject): fallback must guard TUN arrivals since no
	// exemption exists to preserve.
	for _, r := range HostInboundStaleReplyGuardRules(views, nil, nil, nil, false) {
		if !r.IngressNegated {
			continue
		}
		for _, n := range r.Ingress {
			if n == HostInboundReinjectIfname {
				t.Fatalf("stale fallback must not exclude TUN, got %+v", r)
			}
		}
	}
}

func TestHostInboundStaleReplyNetlinkEmitsIngressScope10752(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "deny", SystemServices: []string{"snmp"}, V4Addrs: []string{"192.0.2.10"}, IngressNetdevs: []string{"eth-deny"}},
		{Zone: "open", SystemServices: []string{"any-service"}, V4Addrs: []string{"192.0.2.12"}, IngressNetdevs: []string{"eth-open"}},
	}
	guards := HostInboundStaleReplyGuardRules(views, nil, nil, nil, true)
	p := newBuildPlan(t, "xpf_test_stale_10752", 10)
	emitHostInboundStaleReplyGuards(p, guards)
	if p.err != nil {
		t.Fatalf("netlink guard build failed: %v", p.err)
	}
	if len(p.rules) != len(guards) {
		t.Fatalf("netlink emitted %d rules for %d guards", len(p.rules), len(guards))
	}
	foundPositive, foundNegated := false, false
	for i, exprs := range p.rules {
		got, negated := netlinkGuardIifname(t, p, exprs)
		want := guards[i].Ingress
		if len(want) == 0 {
			if len(got) != 0 {
				t.Fatalf("rule %d: want no iifname, got %v", i, got)
			}
			continue
		}
		if negated != guards[i].IngressNegated {
			t.Fatalf("rule %d: negated=%v, want %v", i, negated, guards[i].IngressNegated)
		}
		if len(got) != len(want) {
			t.Fatalf("rule %d: iifname %v, want %v", i, got, want)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("rule %d: iifname %v, want %v", i, got, want)
			}
		}
		if negated {
			foundNegated = true
		} else {
			foundPositive = true
		}
		// Every guard must be a terminal DROP.
		last := exprs[len(exprs)-1]
		vd, ok := last.(*expr.Verdict)
		if !ok || vd.Kind != expr.VerdictDrop {
			t.Fatalf("rule %d: last expr = %#v, want DROP verdict", i, last)
		}
	}
	if !foundPositive || !foundNegated {
		t.Fatalf("want both positive and negated iifname guards, got positive=%v negated=%v", foundPositive, foundNegated)
	}
}

func guardRuleHasIngressTuple(rules []StaleReplyGuardRule, ingress []string, negated bool, address, family string, proto uint8, port uint16) bool {
	for _, r := range rules {
		if r.Family != family || r.Proto != proto || r.IngressNegated != negated || len(r.Ingress) != len(ingress) {
			continue
		}
		match := true
		for i := range ingress {
			if r.Ingress[i] != ingress[i] {
				match = false
			}
		}
		if !match {
			continue
		}
		foundAddr := false
		for _, a := range r.Addresses {
			if a == address {
				foundAddr = true
			}
		}
		if !foundAddr {
			continue
		}
		for _, p := range r.Ports {
			if p == port {
				return true
			}
		}
	}
	return false
}

func netlinkGuardIifname(t *testing.T, p *nlPlan, exprs []expr.Any) ([]string, bool) {
	t.Helper()
	for i, e := range exprs {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyIIFNAME {
			continue
		}
		if i+1 >= len(exprs) {
			t.Fatalf("iifname meta at end of rule without comparator")
		}
		switch cmp := exprs[i+1].(type) {
		case *expr.Cmp:
			name := string(bytes.TrimRight(cmp.Data, "\x00"))
			if cmp.Op == expr.CmpOpEq {
				return []string{name}, false
			}
			if cmp.Op == expr.CmpOpNeq {
				return []string{name}, true
			}
			t.Fatalf("unexpected iifname cmp op %v", cmp.Op)
		case *expr.Lookup:
			var out []string
			for _, el := range p.setElementsForID(cmp.SetID) {
				out = append(out, string(bytes.TrimRight(el.Key, "\x00")))
			}
			sort.Strings(out)
			return out, cmp.Invert
		default:
			t.Fatalf("unexpected iifname comparator %T", exprs[i+1])
		}
	}
	return nil, false
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
