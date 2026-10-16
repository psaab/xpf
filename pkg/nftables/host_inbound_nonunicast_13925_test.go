package nftables

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestHostInboundNonUnicastNetlink13925(t *testing.T) {
	p := newBuildPlan(t, "xpf_13925", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: []HostInboundZoneView{
			{
				Zone: "untrust", SystemServices: []string{"ssh"},
				V4Addrs: []string{"192.0.2.10"}, V6Addrs: []string{"2001:db8:1392::10"},
				IngressNetdevs: []string{"wan0"},
				IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"wan1"}}},
			},
			{
				Zone: "open", SystemServices: []string{"any-service"},
				V4Addrs: []string{"198.51.100.10"}, V6Addrs: []string{"2001:db8:1392::20"},
				IngressNetdevs: []string{"open0"},
			},
			{
				Zone: "left", SystemServices: []string{"ssh"}, V4Addrs: []string{"192.0.2.30"},
				IngressNetdevs: []string{"shared0"}, IngressDenyNetdevs: []string{"shared0"},
			},
		},
		UnzonedIngressNetdevs:   []string{"loose0"},
		UnzonedIngressVRFSlaves: []string{"loose1"},
	})
	if p.err != nil {
		t.Fatalf("build non-unicast host-inbound plan: %v", p.err)
	}

	classes := []struct {
		name    string
		addrSet string
	}{
		{name: "limited broadcast", addrSet: addrHex(t, "255.255.255.255")},
		{name: "link-scope multicast", addrSet: hex.EncodeToString(net.ParseIP("ff02::").To16())},
	}
	for _, class := range classes {
		t.Run(class.name, func(t *testing.T) {
			closed := netlinkRulesFor13925(p, "wan0", class.addrSet)
			assertScopedAdmitAndDrop13925(t, closed, "closed zone wan0")

			open := netlinkRulesFor13925(p, "open0", class.addrSet)
			var openAccept, openDrop bool
			for _, rule := range open {
				openAccept = openAccept || strings.HasSuffix(rule, "verdict(1)")
				openDrop = openDrop || strings.HasSuffix(rule, "verdict(0)")
			}
			if !openAccept || openDrop {
				t.Fatalf("any-service must accept without a later drop; accept=%t drop=%t rules=%v", openAccept, openDrop, open)
			}

			unleased := netlinkRulesFor13925(p, "loose0", class.addrSet)
			assertAnyDrop13925(t, unleased, "unzoned ingress")
			unleasedVRF := netlinkRulesFor13925(p, "loose1", class.addrSet)
			assertAnyDrop13925(t, unleasedVRF, "unzoned VRF slave")
			ambiguous := netlinkRulesFor13925(p, "shared0", class.addrSet)
			assertAnyDrop13925(t, ambiguous, "ambiguous ingress")

			vrf := netlinkRulesFor13925(p, "wan1", class.addrSet)
			assertScopedAdmitAndDrop13925(t, vrf, "VRF-scoped closed zone")
		})
	}
}

func netlinkRulesFor13925(p *nlPlan, ingress, addrSetHex string) []string {
	ifnameHex := hex.EncodeToString([]byte(ingress))
	var rules []string
	for _, exprs := range p.rules {
		line := canonRule(p, exprs)
		if strings.Contains(line, ifnameHex) && strings.Contains(line, addrSetHex) {
			rules = append(rules, line)
		}
	}
	return rules
}

func assertScopedAdmitAndDrop13925(t *testing.T, rules []string, scope string) {
	t.Helper()
	var accept, drop bool
	for _, rule := range rules {
		accept = accept || strings.HasSuffix(rule, "verdict(1)")
		drop = drop || strings.HasSuffix(rule, "verdict(0)")
	}
	if len(rules) == 0 || !accept || !drop {
		t.Fatalf("%s must carry service-scoped accept(s) and default drop; accept=%t drop=%t rules=%v", scope, accept, drop, rules)
	}
}

func assertAnyDrop13925(t *testing.T, rules []string, scope string) {
	t.Helper()
	for _, rule := range rules {
		if strings.HasSuffix(rule, "verdict(0)") {
			return
		}
	}
	t.Fatalf("%s lacks a non-unicast default drop: %v", scope, rules)
}

// TestHostInboundNonUnicastUDPDelivery13925 sends real UDP payloads through the
// installed production netlink table. A wildcard SNMP-style service socket
// must not receive limited broadcast, ff02::1, or its local solicited-node
// group from a closed zone; admitting `snmp` must restore delivery.
func TestHostInboundNonUnicastUDPDelivery13925(t *testing.T) {
	enterPrivateNetns(t)
	const (
		hostV4 = "192.0.2.2"
		peerV4 = "192.0.2.1"
		hostV6 = "2001:db8:1392::1"
		peerV6 = "2001:db8:1392::2"
	)
	hostLink := mkNamedVeth10751(t, unleasedTestNetdev10751, "v13925host", "v13925peer")
	peerLink, err := netlink.LinkByName("v13925peer")
	if err != nil {
		t.Fatalf("find peer link: %v", err)
	}
	for _, addr := range []struct {
		link netlink.Link
		cidr string
	}{
		{hostLink, hostV4 + "/24"}, {peerLink, peerV4 + "/24"},
		{hostLink, hostV6 + "/64"}, {peerLink, peerV6 + "/64"},
	} {
		mustAddrAdd10751(t, addr.link, addr.cidr)
	}
	waitAddrsValid10751(t, map[string][]string{
		unleasedTestNetdev10751: {hostV6},
		"v13925peer":            {peerV6},
	})
	if err := netlink.LinkSetAllmulticastOn(hostLink); err != nil {
		t.Fatalf("enable IPv6 multicast reception: %v", err)
	}
	hostIface, err := net.InterfaceByName(unleasedTestNetdev10751)
	if err != nil {
		t.Fatalf("find host interface: %v", err)
	}
	installer := NewNetlinkInstaller()
	installServices := func(services []string) {
		t.Helper()
		err := installer.InstallHostInbound(HostInboundSpec{Views: []HostInboundZoneView{{
			Zone: "untrust", SystemServices: services,
			V4Addrs: []string{hostV4}, V6Addrs: []string{hostV6},
			IngressNetdevs: []string{unleasedTestNetdev10751},
		}}})
		if err != nil {
			t.Fatalf("install host-inbound services %v: %v", services, err)
		}
	}

	// Limited broadcast is delivered to a wildcard IPv4 socket only while
	// the ingress zone admits the SNMP UDP/161 service tuple.
	recv4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 161})
	if err != nil {
		t.Fatalf("listen for IPv4 SNMP payload: %v", err)
	}
	defer recv4.Close()
	send4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(peerV4), Port: 0})
	if err != nil {
		t.Fatalf("bind IPv4 peer sender: %v", err)
	}
	defer send4.Close()
	enableBroadcast10751(t, send4)
	sendBroadcast := func(payload []byte) func() error {
		return func() error {
			_, err := send4.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4bcast, Port: 161})
			return err
		}
	}
	installServices([]string{"ssh"})
	if udpExchange10751(t, recv4, sendBroadcast([]byte("closed-limited-broadcast")), 350*time.Millisecond) {
		t.Fatal("closed zone delivered limited-broadcast UDP/161")
	}
	installServices([]string{"snmp"})
	wantBroadcast := []byte("open-limited-broadcast")
	if !udpExchangeRetryWant10751(t, recv4, sendBroadcast(wantBroadcast), wantBroadcast, 200*time.Millisecond, 2*time.Second) {
		t.Fatal("snmp-admitting zone did not deliver limited-broadcast UDP/161")
	}
	if err := recv4.Close(); err != nil {
		t.Fatalf("close IPv4 listener: %v", err)
	}

	sender6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(peerV6), Port: 0})
	if err != nil {
		t.Fatalf("bind IPv6 peer sender: %v", err)
	}
	defer sender6.Close()
	oif := linkIndex10751(t, "v13925peer")
	for _, group := range []struct {
		name string
		addr string
	}{
		{name: "all-nodes", addr: "ff02::1"},
		{name: "solicited-node", addr: "ff02::1:ff00:1"},
	} {
		recv6, err := net.ListenMulticastUDP("udp6", hostIface, &net.UDPAddr{
			IP: net.ParseIP(group.addr), Port: 161,
		})
		if err != nil {
			t.Fatalf("listen for %s UDP/161: %v", group.name, err)
		}
		send := func(payload []byte) func() error {
			return func() error {
				return sendToScope10751(t, sender6, payload, net.ParseIP(group.addr), 161, oif)
			}
		}
		installServices([]string{"ssh"})
		closedPayload := []byte("closed-" + group.name)
		if udpExchange10751(t, recv6, send(closedPayload), 350*time.Millisecond) {
			t.Fatalf("closed zone delivered %s UDP/161", group.name)
		}
		installServices([]string{"snmp"})
		openPayload := []byte("open-" + group.name)
		if !udpExchangeRetryWant10751(t, recv6, send(openPayload), openPayload, 200*time.Millisecond, 2*time.Second) {
			t.Fatalf("snmp-admitting zone did not deliver %s UDP/161", group.name)
		}
		if err := recv6.Close(); err != nil {
			t.Fatalf("close %s listener: %v", group.name, err)
		}
	}
}
