package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundMulticastIngressGuardOrdering11571(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone: "ospf", Protocols: []string{"OSPF"},
			MulticastRules: config.HostInboundMulticastRules([]string{"OSPF"}),
			IngressNetdevs: []string{"ge-ospf"},
		},
		{Zone: "closed", IngressNetdevs: []string{"ge-closed"}},
		{Zone: "wildcard", SystemServices: []string{"any-service"}, IngressNetdevs: []string{"ge-any"}},
		{
			Zone: "addressless-vrrp", Protocols: []string{"vrrp"},
			MulticastRules: config.HostInboundMulticastRules([]string{"vrrp"}),
			IngressNetdevs: []string{"ge-addressless"},
		},
		{Zone: "ambiguous", IngressDenyNetdevs: []string{"ge-ambiguous"}},
		{
			Zone: "fine-deny", Protocols: []string{"vrrp"},
			MulticastRules: config.HostInboundMulticastRules([]string{"vrrp"}),
			IngressNetdevs: []string{"ge-fine"},
		},
	}
	programs := []dpuserspace.JunosHostProgram{{
		Zone: "fine-deny", IngressIfnames: []string{"ge-fine"},
		RulesV4: []config.JunosHostDenyRule{{
			Family: "ip", SrcAny: true, DstAny: true, Verdict: config.JunosHostDrop,
		}},
	}}
	payload := buildHostInboundFilterPayloadWithUnzonedIngress(
		views, nil, nil, []string{"ge-unzoned"}, []string{"ge-vrf-unzoned"},
		programs, nil, true, nil, nil, nil,
	)
	lines := strings.Split(payload, "\n")
	lineIndex := func(parts ...string) int {
		for i, line := range lines {
			match := true
			for _, part := range parts {
				if !strings.Contains(line, part) {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
		return -1
	}

	ospfAccept := lineIndex(`iifname "ge-ospf" ip daddr 224.0.0.5`, "meta l4proto 89", "accept")
	if ospfAccept < 0 {
		t.Fatal("OSPF proto 89 is not admitted on its configured ingress")
	}
	ospfDrop := lineIndex(`iifname "ge-ospf" ip daddr`, "224.0.0.5", "drop")
	if ospfDrop <= ospfAccept {
		t.Fatalf("catalog default-deny must follow the exact OSPF grant: allow=%d drop=%d", ospfAccept, ospfDrop)
	}
	if idx := lineIndex(`iifname "ge-closed" ip daddr`, "224.0.0.5", "accept"); idx >= 0 {
		t.Fatal("an ingress without OSPF must not accept the OSPF group")
	}
	closedDrop := lineIndex(`iifname "ge-closed" ip daddr`, "224.0.0.5", "drop")
	if closedDrop < 0 {
		t.Fatal("an ingress without OSPF has no catalog-group default-deny")
	}

	vrrp6Accept := lineIndex(`iifname "ge-addressless" ip6 daddr ff02::12`, "meta l4proto 112", "accept")
	if vrrp6Accept < 0 {
		t.Fatal("addressless VRRP ingress did not admit VRRPv6 proto 112")
	}
	if wildcard := `iifname "ge-any" ip daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")) + " accept"; lineIndex(wildcard) < 0 {
		t.Fatal("explicit any-service did not retain its IPv4 catalog-group wildcard")
	}
	if lineIndex(`iifname "ge-ambiguous" ip daddr`, "224.0.0.5", "drop") < 0 {
		t.Fatal("ambiguous ingress is not fail-closed for catalog groups")
	}
	if lineIndex(`iifname "ge-unzoned" ip daddr`, "224.0.0.5", "drop") < 0 {
		t.Fatal("unzoned ingress is not fail-closed for catalog groups")
	}
	if lineIndex(`meta sdifname "ge-vrf-unzoned" ip6 daddr`, "ff02::12", "drop") < 0 {
		t.Fatal("unzoned VRF slave is not fail-closed for IPv6 catalog groups")
	}

	replyAccept := lineIndex("ct state established,related ct direction reply accept")
	genericAccept := lineIndex("ct state established,related accept")
	if replyAccept < 0 || genericAccept < 0 || closedDrop >= replyAccept || closedDrop >= genericAccept {
		t.Fatalf("catalog drop must precede established accepts: drop=%d reply=%d generic=%d", closedDrop, replyAccept, genericAccept)
	}

	fineChain := xnft.HostInboundJunosHostChainName(0, "fine-deny")
	fineJump := lineIndex(`iifname "ge-fine" ip daddr `+nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")), "jump "+fineChain)
	fineAccept := lineIndex(`iifname "ge-fine" ip daddr 224.0.0.18`, "meta l4proto 112", "accept")
	if fineJump < 0 || fineAccept < 0 || fineJump >= fineAccept {
		t.Fatalf("fine junos-host jump must precede the multicast grant: jump=%d accept=%d", fineJump, fineAccept)
	}
	chainStart := strings.Index(payload, "  chain "+fineChain+" {")
	if chainStart < 0 {
		t.Fatalf("fine junos-host chain %q was not rendered", fineChain)
	}
	chainBody := payload[chainStart:]
	if end := strings.Index(chainBody, "\n  }"); end >= 0 {
		chainBody = chainBody[:end]
	}
	if !strings.Contains(chainBody, " drop") {
		t.Fatal("the fine junos-host program has no terminal deny to protect from the multicast grant")
	}
}

func TestHostInboundAddresslessIngressKeepsMulticastPolicy11571(t *testing.T) {
	const unzonedIngress = "ge-unzoned-no-address"
	const zonedIngress = "ge-zone-no-address"
	views := []dpuserspace.ZoneHostInboundView{{
		Zone:           "addressless-vrrp",
		Protocols:      []string{"vrrp"},
		MulticastRules: config.HostInboundMulticastRules([]string{"vrrp"}),
		IngressNetdevs: []string{zonedIngress},
	}}
	if !hostInboundHasEnforceableView(views) ||
		!hostInboundHasIngressScope(views, []string{unzonedIngress}, nil) {
		t.Fatal("addressless zoned and unzoned ingresses must retain host-inbound enforcement")
	}

	payload := buildHostInboundFilterPayloadWithUnzonedIngress(
		views, nil, nil, []string{unzonedIngress}, nil, nil, nil, true, nil, nil, nil,
	)
	for _, rule := range []string{
		`iifname "` + zonedIngress + `" ip daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")) + " drop",
		`iifname "` + unzonedIngress + `" ip daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")) + " drop",
	} {
		if !strings.Contains(payload, rule) {
			t.Fatalf("main ruleset omitted addressless-ingress catalog drop %q:\n%s", rule, payload)
		}
	}

	fence := buildHostInboundFencePayloadWithIngress(
		views, nil, nil, nil, nil, nil, nil, []string{unzonedIngress}, nil,
	)
	for _, rule := range []string{
		`iifname "` + zonedIngress + `" ip6 daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip6")) + " drop",
		`iifname "` + unzonedIngress + `" ip daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")) + " drop",
	} {
		if !strings.Contains(fence, rule) {
			t.Fatalf("cold-boot fence omitted addressless-ingress catalog drop %q:\n%s", rule, fence)
		}
	}

	uncoveredV4, uncoveredV6 := []string{"192.0.2.2"}, []string{"2001:db8::2"}
	gap := buildHostInboundGapFencePayload(
		nil, uncoveredV4, uncoveredV6, nil, nil, nil, nil, nil, nil, nil,
	)
	for _, rule := range []string{
		"ip daddr " + nftAddrSet(uncoveredV4) + " drop",
		"ip6 daddr " + nftAddrSet(uncoveredV6) + " drop",
	} {
		if !strings.Contains(gap, rule) {
			t.Fatalf("additive gap fence omitted its uncovered address drop %q:\n%s", rule, gap)
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		if strings.Contains(gap, family+" daddr "+nftAddrSet(config.HostInboundMulticastGroupsForFamily(family))+" drop") {
			t.Fatalf("additive gap fence must not override retained multicast grants (%s):\n%s", family, gap)
		}
	}
}
