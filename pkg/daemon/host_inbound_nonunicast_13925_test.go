package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #13925 (H04-01): non-catalog host-bound destinations — IPv4 limited
// broadcast (255.255.255.255) and IPv6 link-scope multicast outside the
// #11571 routing catalog (ff02::1, solicited-node groups) — reached the
// chain's `policy accept` fall-through on zoned ingress, bypassing the
// per-zone host-inbound gate that judges unicast. The kernel chain now
// judges those destinations by the ingress zone's service/protocol set
// (all-nodes/solicited-node ICMPv6 echo stays gated on `ping`), preserves the
// existing ND admits and MLD fall-through, and fails closed for unzoned/ambiguous ingress.
//
// RED-on-revert: deleting emitHostInboundNonUnicastIngressGuards (text)
// and its netlink twin removes every rule asserted below.

func nonUnicastLines13925(payload, needle string) []string {
	var out []string
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, needle) {
			out = append(out, line)
		}
	}
	return out
}

func hasLine13925(lines []string, wants ...string) bool {
	for _, line := range lines {
		ok := true
		for _, w := range wants {
			if !strings.Contains(line, w) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestHostInboundNonUnicastIsScopedByIngressZone13925(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "open-zone",
			SystemServices: []string{"snmp", "ping"},
			V4Addrs:        []string{"192.0.2.1"},
			V6Addrs:        []string{"2001:db8::1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "closed-zone",
			V4Addrs:        []string{"198.51.100.1"},
			V6Addrs:        []string{"2001:db8:1::1"},
			IngressNetdevs: []string{"ge-0-0-1"},
		},
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)

	// IPv4 limited broadcast: service-scoped accept only for the zone
	// admitting snmp; the closed zone hits the broadcast drop.
	bcast := nonUnicastLines13925(payload, "255.255.255.255")
	if !hasLine13925(bcast, `iifname "ge-0-0-0"`, "udp dport 161", "accept") {
		t.Fatalf("limited broadcast has no snmp-scoped accept for open-zone:\n%s", payload)
	}
	if hasLine13925(bcast, `iifname "ge-0-0-1"`, "accept") {
		t.Fatalf("closed-zone must not accept limited broadcast:\n%s", payload)
	}
	if !hasLine13925(bcast, `iifname "ge-0-0-1"`, "drop") {
		t.Fatalf("limited broadcast on closed-zone must hit a drop:\n%s", payload)
	}

	// IPv6 link-scope multicast (ff02::/16): same service scoping.
	link := nonUnicastLines13925(payload, "ff02::/16")
	if !hasLine13925(link, `iifname "ge-0-0-0"`, "udp dport 161", "accept") {
		t.Fatalf("link-scope multicast has no snmp-scoped accept for open-zone:\n%s", payload)
	}
	if hasLine13925(link, `iifname "ge-0-0-1"`, "accept") {
		t.Fatalf("link-scope multicast must not be accepted for closed-zone:\n%s", payload)
	}

	// ff02::1 echo-request stays gated on `ping`: open-zone (ping) admits
	// icmpv6 echo-request to ff02::/16, closed-zone drops it.
	if !hasLine13925(link, `iifname "ge-0-0-0"`, "icmpv6 type echo-request", "accept") {
		t.Fatalf("ff02::1 echo-request must be admitted for the ping zone:\n%s", payload)
	}
	if hasLine13925(link, `iifname "ge-0-0-1"`, "icmpv6 type echo-request", "accept") {
		t.Fatalf("ff02::1 echo-request must not be admitted for the closed zone:\n%s", payload)
	}

	// Unicast local delivery remains governed by the pre-existing same
	// per-zone service gate.
	unicast := nonUnicastLines13925(payload, "192.0.2.1")
	if !hasLine13925(unicast, `iifname "ge-0-0-0"`, "udp dport 161", "accept") {
		t.Fatalf("unicast service admission changed alongside non-unicast enforcement:\n%s", payload)
	}
	// Ordering: the non-unicast guard must run before the residual
	// established accept, or conntrack state bypasses the zone decision.
	guard := strings.Index(payload, "255.255.255.255")
	residual := strings.Index(payload, "    ct state established,related accept")
	if guard < 0 || residual < 0 || guard > residual {
		t.Fatalf("non-unicast guard must precede residual established accept:\n%s", payload)
	}

	// Catalog parity: the #11571 routing-multicast guard is unchanged.
	if !strings.Contains(payload, "224.0.0.5") {
		t.Fatalf("catalog multicast guard missing:\n%s", payload)
	}
	// ND keeps its existing global accept; link-scope MLD retains the prior
	// base-chain fall-through without introducing a global ACCEPT.
	if !strings.Contains(payload, "icmpv6 type { 133, 134, 135, 136 }") {
		t.Fatalf("global ND-only accept missing (Redirect 137 must not be global):\n%s", payload)
	}
	if !strings.Contains(payload, "ip6 daddr ff02::/16 icmpv6 type { 130, 131, 132, 143 } return") {
		t.Fatalf("link-scope MLD must retain fall-through before the ff02 gate:\n%s", payload)
	}
}

func TestHostInboundNonUnicastUnzonedAndAnyService13925(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "any-zone",
			SystemServices: []string{"any-service"},
			V4Addrs:        []string{"192.0.2.1"},
			V6Addrs:        []string{"2001:db8::1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
	}
	payload := buildHostInboundFilterPayloadWithUnzonedIngress(
		views, nil, nil, []string{"ge-unzoned"}, nil, nil, nil, true, nil, nil, nil, dhcpBackstopLists{},
	)
	// any-service zone accepts its non-unicast classes wholesale.
	bcast := nonUnicastLines13925(payload, "255.255.255.255")
	if !hasLine13925(bcast, `iifname "ge-0-0-0"`, "accept") || hasLine13925(bcast, `iifname "ge-0-0-0"`, "drop") {
		t.Fatalf("any-service zone must accept limited broadcast without a drop:\n%s", payload)
	}
	// Unzoned ingress drops both classes.
	if !hasLine13925(bcast, `iifname "ge-unzoned"`, "drop") {
		t.Fatalf("unzoned ingress must drop limited broadcast:\n%s", payload)
	}
	link := nonUnicastLines13925(payload, "ff02::/16")
	if !hasLine13925(link, `iifname "ge-0-0-0"`, "accept") || hasLine13925(link, `iifname "ge-0-0-0"`, "drop") {
		t.Fatalf("any-service zone must accept link-scope multicast without a drop:\n%s", payload)
	}
	if !hasLine13925(link, `iifname "ge-unzoned"`, "drop") {
		t.Fatalf("unzoned ingress must drop link-scope multicast:\n%s", payload)
	}
	// The cold-boot fence has no zone permits; it must deny these same
	// destinations until the current host-inbound generation is installed.
	// The full cold-boot fence preserves mandatory ND/MLD admits ahead of
	// non-unicast drops, which precede its established-flow accept.
	fence := buildFenceTablePayload(
		xnft.HostInboundTableName, nftHostInboundPriority, views,
		nil, nil, nil, nil, nil, nil, true, []string{"ge-unzoned"}, nil, dhcpBackstopLists{},
	)
	if !strings.Contains(fence, "255.255.255.255") || !strings.Contains(fence, "ff02::/16") {
		t.Fatalf("cold-boot fence must deny both non-unicast classes:\n%s", fence)
	}
	mld := strings.Index(fence, "ip6 daddr ff02::/16 icmpv6 type { 130, 131, 132, 143 } return")
	nd := strings.Index(fence, "icmpv6 type { 133, 134, 135, 136 } accept")
	guard := strings.Index(fence, "ff02::/16 drop")
	established := strings.Index(fence, "ct state established,related accept")
	if mld < 0 || nd < 0 || guard < 0 || established < 0 ||
		mld > guard || nd > guard || guard > established {
		t.Fatalf("cold-boot fence must preserve MLD fall-through/ND then gate before established:\n%s", fence)
	}
}
