package dhcprelay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/psaab/xpf/pkg/config"
)

// RFC 8415 §19.1.1 permits a link-local Relay-Forw link-address when no
// GUA/ULA exists, with Interface-Id required when the link-address cannot
// identify the return link (#10198).

func TestSelectDHCPv6LinkAddressFallback10198(t *testing.T) {
	gua := net.ParseIP("2001:db8:1::1")
	ula := net.ParseIP("fd00::1")
	ll := net.ParseIP("fe80::1")
	v4 := net.ParseIP("192.0.2.1")
	cases := []struct {
		name  string
		addrs []net.IP
		want  net.IP
	}{
		{"gua first", []net.IP{gua, ula, ll}, gua},
		{"first global remains preferred", []net.IP{ll, ula, gua}, ula},
		{"ula beats link-local", []net.IP{ll, ula}, ula},
		{"ula beats link-local reversed", []net.IP{ula, ll}, ula},
		{"link-local-only fallback", []net.IP{ll}, ll},
		{"link-local among unusable", []net.IP{v4, net.IPv6unspecified, net.ParseIP("ff02::1"), net.ParseIP("::1"), ll}, ll},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectDHCPv6LinkAddress(tc.addrs)
			if err != nil {
				t.Fatalf("selectDHCPv6LinkAddress(%v) error: %v", tc.addrs, err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("selectDHCPv6LinkAddress(%v) = %v, want %v", tc.addrs, got, tc.want)
			}
		})
	}
	if _, err := selectDHCPv6LinkAddress(nil); err == nil {
		t.Fatal("empty address list must return an error")
	}
	if _, err := selectDHCPv6LinkAddress([]net.IP{v4, net.IPv6unspecified}); err == nil {
		t.Fatal("IPv4/unspecified-only list must return an error")
	}
}

func TestBuildRelayForwardV6LinkLocalRequiresInterfaceID10198(t *testing.T) {
	linkLocal := net.ParseIP("fe80::1")
	peer := net.ParseIP("fe80::2")

	forward, err := buildRelayForwardV6(newDHCPV6TestMessage(t), linkLocal, peer, []byte("ge-0/0/0.0"))
	if err != nil {
		t.Fatalf("direct link-local Relay-Forw with Interface-ID: %v", err)
	}
	if !forward.LinkAddr.Equal(linkLocal) {
		t.Fatalf("link-address = %v, want %v", forward.LinkAddr, linkLocal)
	}
	if got := string(forward.Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("Interface-ID = %q, want authored interface", got)
	}

	if _, err := buildRelayForwardV6(newDHCPV6TestMessage(t), linkLocal, peer, nil); err == nil {
		t.Fatal("direct link-local Relay-Forw without Interface-ID must be rejected")
	}

	nested, err := dhcpv6.EncapsulateRelay(newDHCPV6TestMessage(t), dhcpv6.MessageTypeRelayForward, linkLocal, peer)
	if err != nil {
		t.Fatalf("EncapsulateRelay: %v", err)
	}
	if _, err := buildRelayForwardV6(nested, linkLocal, peer, []byte("ge-0/0/0.0")); err == nil {
		t.Fatal("nested link-local Relay-Forw must stay rejected even with Interface-ID")
	}

	if _, err := buildRelayForwardV6(newDHCPV6TestMessage(t), net.ParseIP("2001:db8:1::1"), peer, nil); err != nil {
		t.Fatalf("direct GUA Relay-Forw without Interface-ID must keep working: %v", err)
	}
}

func TestDHCPV6LinkLocalOnlyRelaysForward10198(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	m := NewManager()
	m.v6.resolveLink = func(string) (net.IP, error) { return net.ParseIP("fe80::1"), nil }
	m.v6.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort, Zone: name}
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		if err := client.JoinGroup(client.iface, client.group); err != nil {
			return dhcpV6Sockets{}, err
		}
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	m.SetMasterGate(func(string) bool { return true })
	m.Apply(context.Background(), &config.DHCPRelayConfig{V6: &config.DHCPRelayV6Config{
		ServerGroups: map[string]*config.DHCPRelayV6ServerGroup{
			"sg6": {Name: "sg6", Servers: []string{"2001:db8::5"}},
		},
		Groups: map[string]*config.DHCPRelayV6Group{
			"g6": {Name: "g6", Interfaces: []string{"ge-0/0/0.0"}, ActiveServerGroup: "sg6"},
		},
	}})
	defer m.Stop()
	client.push(newDHCPV6TestMessage(t).ToBytes())
	deadline := time.Now().Add(time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() != 1 {
		t.Fatalf("link-local-only relay forwarded %d requests, want 1", server.writeCount())
	}
	forward, err := dhcpv6.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("parse forwarded request: %v", err)
	}
	relay := forward.(*dhcpv6.RelayMessage)
	if !relay.LinkAddr.Equal(net.ParseIP("fe80::1")) {
		t.Fatalf("Relay-Forw link-address = %v, want fe80::1", relay.LinkAddr)
	}
	if got := string(relay.Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("Relay-Forw Interface-ID = %q, want ge-0/0/0.0", got)
	}
}

func TestDHCPV6UpstreamBindAddrSelection10198(t *testing.T) {
	const (
		ifaceName = "ix0"
		port      = dhcpv6RelayPort
	)
	cases := []struct {
		name string
		ip   net.IP
		want string
	}{
		{"gua exact", net.ParseIP("2001:db8:1::1"), (&net.UDPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: port}).String()},
		{"ula exact", net.ParseIP("fd00::1"), (&net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: port}).String()},
		{"link-local route-selected fallback", net.ParseIP("fe80::1"), (&net.UDPAddr{IP: net.IPv6unspecified, Port: port}).String()},
		{"nil fallback", nil, (&net.UDPAddr{IP: net.IPv6unspecified, Port: port}).String()},
		{"unspecified fallback", net.IPv6unspecified, (&net.UDPAddr{IP: net.IPv6unspecified, Port: port}).String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dhcpV6UpstreamBindAddr(tc.ip, ifaceName, port)
			if got != tc.want {
				t.Fatalf("dhcpV6UpstreamBindAddr(%v) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

func TestDHCPv6PerInterfaceServerBindDemux10198(t *testing.T) {
	var addresses []net.IP
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.To16() == nil || ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
				continue
			}
			duplicate := false
			for _, candidate := range addresses {
				if candidate.Equal(ip) {
					duplicate = true
					break
				}
			}
			if !duplicate {
				addresses = append(addresses, append(net.IP(nil), ip.To16()...))
			}
		}
	}
	if len(addresses) < 2 {
		t.Skipf("need two local GUA/ULA addresses for real-socket demux, found %d", len(addresses))
	}
	listenConfig := dhcpV6ListenConfig("")
	firstAddr := dhcpV6UpstreamBindAddr(addresses[0], "", 0)
	firstRaw, err := listenConfig.ListenPacket(context.Background(), "udp6", firstAddr)
	if err != nil {
		t.Fatalf("listen first exact upstream address %q: %v", firstAddr, err)
	}
	defer firstRaw.Close()
	first, ok := firstRaw.(*net.UDPConn)
	if !ok {
		t.Fatalf("first upstream listener type = %T, want *net.UDPConn", firstRaw)
	}
	port := first.LocalAddr().(*net.UDPAddr).Port
	secondAddr := dhcpV6UpstreamBindAddr(addresses[1], "", port)
	secondRaw, err := listenConfig.ListenPacket(context.Background(), "udp6", secondAddr)
	if err != nil {
		t.Fatalf("listen second exact upstream address %q: %v", secondAddr, err)
	}
	defer secondRaw.Close()
	second, ok := secondRaw.(*net.UDPConn)
	if !ok {
		t.Fatalf("second upstream listener type = %T, want *net.UDPConn", secondRaw)
	}

	firstSender, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: addresses[0], Port: port})
	if err != nil {
		t.Fatalf("dial first upstream destination: %v", err)
	}
	defer firstSender.Close()
	secondSender, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: addresses[1], Port: port})
	if err != nil {
		t.Fatalf("dial second upstream destination: %v", err)
	}
	defer secondSender.Close()
	if _, err := firstSender.Write([]byte("reply-one")); err != nil {
		t.Fatalf("send first upstream reply: %v", err)
	}
	if _, err := secondSender.Write([]byte("reply-two")); err != nil {
		t.Fatalf("send second upstream reply: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	if err := first.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set first read deadline: %v", err)
	}
	if err := second.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set second read deadline: %v", err)
	}
	firstData := make([]byte, 32)
	n, _, err := first.ReadFromUDP(firstData)
	if err != nil {
		t.Fatalf("read first per-interface reply: %v", err)
	}
	if string(firstData[:n]) != "reply-one" {
		t.Fatalf("first per-interface socket received %q, want reply-one", firstData[:n])
	}
	secondData := make([]byte, 32)
	n, _, err = second.ReadFromUDP(secondData)
	if err != nil {
		t.Fatalf("read second per-interface reply: %v", err)
	}
	if string(secondData[:n]) != "reply-two" {
		t.Fatalf("second per-interface socket received %q, want reply-two", secondData[:n])
	}
}

func TestDHCPv6ExactWildcardCoexistence10198(t *testing.T) {
	var address net.IP
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range ifaceAddrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.To16() != nil && ip.To4() == nil &&
				!ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() &&
				!ip.IsLinkLocalUnicast() && ip.IsGlobalUnicast() {
				address = append(net.IP(nil), ip.To16()...)
				break
			}
		}
		if address != nil {
			break
		}
	}
	if address == nil {
		t.Skip("need one local GUA/ULA for exact-vs-wildcard coexistence")
	}

	listenConfig := dhcpV6ListenConfig("")
	exactRaw, err := listenConfig.ListenPacket(context.Background(), "udp6",
		dhcpV6UpstreamBindAddr(address, "", 0))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("exact UDP6 listener requires network capability: %v", err)
		}
		t.Fatalf("listen exact upstream address: %v", err)
	}
	defer exactRaw.Close()
	exact, ok := exactRaw.(*net.UDPConn)
	if !ok {
		t.Fatalf("exact listener type = %T, want *net.UDPConn", exactRaw)
	}
	port := exact.LocalAddr().(*net.UDPAddr).Port
	wildcardRaw, err := listenConfig.ListenPacket(context.Background(), "udp6",
		(&net.UDPAddr{IP: net.IPv6unspecified, Port: port}).String())
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("wildcard UDP6 listener requires network capability: %v", err)
		}
		t.Fatalf("listen wildcard upstream address: %v", err)
	}
	defer wildcardRaw.Close()
	wildcard, ok := wildcardRaw.(*net.UDPConn)
	if !ok {
		t.Fatalf("wildcard listener type = %T, want *net.UDPConn", wildcardRaw)
	}

	const packets = 20
	senders := make([]*net.UDPConn, 0, packets)
	defer func() {
		for _, sender := range senders {
			_ = sender.Close()
		}
	}()
	for i := 0; i < packets; i++ {
		sender, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: address, Port: port})
		if err != nil {
			t.Fatalf("dial exact destination %d: %v", i, err)
		}
		senders = append(senders, sender)
		if _, err := sender.Write([]byte{byte(i), 0x5a}); err != nil {
			t.Fatalf("send exact destination %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	if err := exact.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set exact read deadline: %v", err)
	}
	seen := make(map[byte]bool, packets)
	for i := 0; i < packets; i++ {
		payload := make([]byte, 2)
		n, _, err := exact.ReadFromUDP(payload)
		if err != nil {
			t.Fatalf("read exact packet %d: %v", i, err)
		}
		if n != len(payload) || payload[1] != 0x5a {
			t.Fatalf("exact packet %d payload = %x, want two-byte marker", i, payload[:n])
		}
		seen[payload[0]] = true
	}
	if len(seen) != packets {
		t.Fatalf("exact socket received %d distinct packets, want %d", len(seen), packets)
	}
	if err := wildcard.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set wildcard exact-phase deadline: %v", err)
	}
	if n, _, err := wildcard.ReadFromUDP(make([]byte, 2)); err == nil {
		t.Fatalf("wildcard socket received %d exact-destination bytes", n)
	}

	wildcardSender, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.IPv6loopback, Port: port})
	if err != nil {
		t.Fatalf("dial wildcard destination: %v", err)
	}
	defer wildcardSender.Close()
	if _, err := wildcardSender.Write([]byte("wildcard")); err != nil {
		t.Fatalf("send wildcard destination: %v", err)
	}
	if err := wildcard.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set wildcard read deadline: %v", err)
	}
	payload := make([]byte, 32)
	n, _, err := wildcard.ReadFromUDP(payload)
	if err != nil {
		t.Fatalf("read wildcard destination: %v", err)
	}
	if string(payload[:n]) != "wildcard" {
		t.Fatalf("wildcard payload = %q, want wildcard", payload[:n])
	}
}

func TestDHCPv6ReplyDispatcherRoutesByInterfaceID10198(t *testing.T) {
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(ctx context.Context) (net.PacketConn, error) {
		listen := dhcpV6ListenConfig("")
		return listen.ListenPacket(ctx, "udp6", "[::1]:0")
	}
	sender, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("real UDP6 dispatcher socket requires network capability: %v", err)
		}
		t.Fatalf("listen dispatcher sender: %v", err)
	}
	defer sender.Close()
	senderAddr := sender.LocalAddr().(*net.UDPAddr)
	allowed := []*net.UDPAddr{{IP: net.ParseIP("::1"), Port: senderAddr.Port}}
	clientA := newFakeConn()
	clientB := newFakeConn()
	relayA := &dhcpV6Relay{ifaceName: "ll-a", kernelName: "lo"}
	relayB := &dhcpV6Relay{ifaceName: "ll-b", kernelName: "lo"}
	server, releaseA, err := dispatcher.register(context.Background(), relayA, clientA, allowed, []byte("ll-a"))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("real UDP6 dispatcher socket requires network capability: %v", err)
		}
		t.Fatalf("register first dispatcher target: %v", err)
	}
	defer releaseA()
	_, releaseB, err := dispatcher.register(context.Background(), relayB, clientB, allowed, []byte("ll-b"))
	if err != nil {
		t.Fatalf("register second dispatcher target: %v", err)
	}
	defer releaseB()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	innerA := newDHCPV6TestMessage(t)
	replyA := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("::1"),
	}
	replyA.AddOption(dhcpv6.OptInterfaceID([]byte("ll-a")))
	replyA.AddOption(dhcpv6.OptRelayMessage(innerA))
	innerB := newDHCPV6TestMessage(t)
	replyB := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:2::1"),
		PeerAddr:    net.ParseIP("::1"),
	}
	replyB.AddOption(dhcpv6.OptInterfaceID([]byte("ll-b")))
	replyB.AddOption(dhcpv6.OptRelayMessage(innerB))
	if _, err := sender.WriteToUDP(replyA.ToBytes(), serverAddr); err != nil {
		t.Fatalf("send first Interface-ID reply: %v", err)
	}
	if _, err := sender.WriteToUDP(replyB.ToBytes(), serverAddr); err != nil {
		t.Fatalf("send second Interface-ID reply: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for (clientA.writeCount() == 0 || clientB.writeCount() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if clientA.writeCount() != 1 || clientB.writeCount() != 1 {
		t.Fatalf("dispatcher writes = %d/%d, want one reply per Interface-ID", clientA.writeCount(), clientB.writeCount())
	}
	if got := clientA.firstWrite(t); !bytes.Equal(got, innerA.ToBytes()) {
		t.Fatalf("Interface-ID ll-a payload = %x, want %x", got, innerA.ToBytes())
	}
	if got := clientB.firstWrite(t); !bytes.Equal(got, innerB.ToBytes()) {
		t.Fatalf("Interface-ID ll-b payload = %x, want %x", got, innerB.ToBytes())
	}
}

func TestDHCPv6ReplyDispatcherDisambiguatesDuplicateInterfaceID10198(t *testing.T) {
	server := newFakeConn()
	server.srcAddr = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 68}
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) {
		return server, nil
	}
	clientA := newFakeConn()
	clientB := newFakeConn()
	relayA := &dhcpV6Relay{
		ifaceName:  "ll-shared-a",
		kernelName: "lo",
		linkAddr:   net.ParseIP("2001:db8:10::1"),
	}
	relayB := &dhcpV6Relay{
		ifaceName:  "ll-shared-b",
		kernelName: "lo",
		linkAddr:   net.ParseIP("2001:db8:20::1"),
	}
	allowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 1), Port: 68}}
	_, releaseA, err := dispatcher.register(context.Background(), relayA, clientA, allowed, []byte("shared"))
	if err != nil {
		t.Fatalf("register first duplicate-ID target: %v", err)
	}
	defer releaseA()
	_, releaseB, err := dispatcher.register(context.Background(), relayB, clientB, allowed, []byte("shared"))
	if err != nil {
		t.Fatalf("register second duplicate-ID target: %v", err)
	}
	defer releaseB()

	innerA := newDHCPV6TestMessage(t)
	replyA := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    relayA.linkAddr,
		PeerAddr:    net.ParseIP("::1"),
	}
	replyA.AddOption(dhcpv6.OptInterfaceID([]byte("shared")))
	replyA.AddOption(dhcpv6.OptRelayMessage(innerA))
	innerB := newDHCPV6TestMessage(t)
	replyB := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    relayB.linkAddr,
		PeerAddr:    net.ParseIP("::1"),
	}
	replyB.AddOption(dhcpv6.OptInterfaceID([]byte("shared")))
	replyB.AddOption(dhcpv6.OptRelayMessage(innerB))
	server.push(replyA.ToBytes())
	server.push(replyB.ToBytes())
	deadline := time.Now().Add(time.Second)
	for (clientA.writeCount() == 0 || clientB.writeCount() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if clientA.writeCount() != 1 || clientB.writeCount() != 1 {
		t.Fatalf("duplicate Interface-ID dispatch writes = %d/%d, want one each", clientA.writeCount(), clientB.writeCount())
	}
	if got := clientA.firstWrite(t); !bytes.Equal(got, innerA.ToBytes()) {
		t.Fatalf("duplicate Interface-ID link-address A payload = %x, want %x", got, innerA.ToBytes())
	}
	if got := clientB.firstWrite(t); !bytes.Equal(got, innerB.ToBytes()) {
		t.Fatalf("duplicate Interface-ID link-address B payload = %x, want %x", got, innerB.ToBytes())
	}
	ambiguousClientA := newFakeConn()
	ambiguousClientB := newFakeConn()
	ambiguousLink := net.ParseIP("2001:db8:30::1")
	ambiguousRelayA := &dhcpV6Relay{ifaceName: "ll-ambiguous-a", kernelName: "lo", linkAddr: ambiguousLink}
	ambiguousRelayB := &dhcpV6Relay{ifaceName: "ll-ambiguous-b", kernelName: "lo", linkAddr: ambiguousLink}
	_, releaseAmbiguousA, err := dispatcher.register(context.Background(), ambiguousRelayA, ambiguousClientA, allowed, []byte("ambiguous"))
	if err != nil {
		t.Fatalf("register first ambiguous target: %v", err)
	}
	defer releaseAmbiguousA()
	_, releaseAmbiguousB, err := dispatcher.register(context.Background(), ambiguousRelayB, ambiguousClientB, allowed, []byte("ambiguous"))
	if err != nil {
		t.Fatalf("register second ambiguous target: %v", err)
	}
	defer releaseAmbiguousB()
	ambiguousDrops := dispatcher.droppedAmbiguous.Load()
	ambiguousReply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    ambiguousLink,
		PeerAddr:    net.ParseIP("::1"),
	}
	ambiguousReply.AddOption(dhcpv6.OptInterfaceID([]byte("ambiguous")))
	ambiguousReply.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	server.push(ambiguousReply.ToBytes())
	deadline = time.Now().Add(time.Second)
	for dispatcher.droppedAmbiguous.Load() == ambiguousDrops && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := dispatcher.droppedAmbiguous.Load(); got != ambiguousDrops+1 {
		t.Fatalf("ambiguous Interface-ID drops=%d, want %d", got, ambiguousDrops+1)
	}
	if ambiguousClientA.writeCount() != 0 || ambiguousClientB.writeCount() != 0 {
		t.Fatalf("ambiguous Interface-ID was forwarded: writes=%d/%d", ambiguousClientA.writeCount(), ambiguousClientB.writeCount())
	}
	parseBefore := dispatcher.droppedParse.Load()
	emptyBefore := dispatcher.droppedEmptyIID.Load()
	unknownBefore := dispatcher.droppedUnknown.Load()
	emptyReply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    ambiguousLink,
		PeerAddr:    net.ParseIP("::1"),
	}
	emptyReply.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	unknownReply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    ambiguousLink,
		PeerAddr:    net.ParseIP("::1"),
	}
	unknownReply.AddOption(dhcpv6.OptInterfaceID([]byte("unknown")))
	unknownReply.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	server.push([]byte{byte(dhcpv6.MessageTypeRelayReply)})
	server.push(emptyReply.ToBytes())
	server.push(unknownReply.ToBytes())
	deadline = time.Now().Add(time.Second)
	for (dispatcher.droppedParse.Load() == parseBefore ||
		dispatcher.droppedEmptyIID.Load() == emptyBefore ||
		dispatcher.droppedUnknown.Load() == unknownBefore) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := dispatcher.droppedParse.Load(); got != parseBefore+1 {
		t.Fatalf("dispatcher parse drops=%d, want %d", got, parseBefore+1)
	}
	if got := dispatcher.droppedEmptyIID.Load(); got != emptyBefore+1 {
		t.Fatalf("dispatcher empty-IID drops=%d, want %d", got, emptyBefore+1)
	}
	if got := dispatcher.droppedUnknown.Load(); got != unknownBefore+1 {
		t.Fatalf("dispatcher unknown-IID drops=%d, want %d", got, unknownBefore+1)
	}
}

func TestDHCPv6ReplyDispatcherStatsSyntheticRow10198(t *testing.T) {
	m := NewManager()
	m.v6.mu.Lock()
	m.v6.relays["ll-stats-a"] = &dhcpV6Relay{ifaceName: "ll-stats-a", kernelName: "lo"}
	m.v6.relays["ll-stats-b"] = &dhcpV6Relay{ifaceName: "ll-stats-b", kernelName: "lo"}
	dispatcher := m.v6.replyDispatcher
	dispatcher.droppedParse.Add(1)
	dispatcher.droppedEmptyIID.Add(2)
	dispatcher.droppedUnknown.Add(3)
	dispatcher.droppedAmbiguous.Add(4)
	m.v6.mu.Unlock()

	var dispatcherRows int
	var got RelayStats
	for _, stat := range m.Stats() {
		if stat.Interface != "<dhcpv6-reply-dispatcher>" {
			continue
		}
		dispatcherRows++
		got = stat
	}
	if dispatcherRows != 1 {
		t.Fatalf("dispatcher Stats rows=%d, want one synthetic row", dispatcherRows)
	}
	if got.Family != "inet6" ||
		got.RepliesDroppedDispatcherParse != 1 ||
		got.RepliesDroppedDispatcherEmptyIID != 2 ||
		got.RepliesDroppedDispatcherUnknownIID != 3 ||
		got.RepliesDroppedDispatcherAmbiguous != 4 {
		t.Fatalf("dispatcher Stats row = %+v, want aggregate 1/2/3/4", got)
	}
}

func TestDHCPv6ServerLoopRoutesMismatchedInterfaceID10198(t *testing.T) {
	server := newFakeConn()
	dispatcherServer := newFakeConn()
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) {
		return dispatcherServer, nil
	}
	targetClient := newFakeConn()
	targetRelay := &dhcpV6Relay{
		ifaceName:  "ll-mismatch-target",
		kernelName: "lo",
		linkAddr:   net.ParseIP("2001:db8:50::1"),
	}
	targetAllowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 1), Port: 68}}
	_, release, err := dispatcher.register(context.Background(), targetRelay, targetClient, targetAllowed, []byte("target"))
	if err != nil {
		t.Fatalf("register mismatched-IID target: %v", err)
	}
	defer release()

	relay := &dhcpV6Relay{ifaceName: "ll-mismatch-owner", kernelName: "lo"}
	ownerAllowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 2), Port: 68}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&dhcpV6Manager{}).runDHCPV6ServerLoop(ctx, relay, server, newFakeConn(), ownerAllowed, []byte("owner"), dispatcher)
		close(done)
	}()
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    targetRelay.linkAddr,
		PeerAddr:    net.ParseIP("::1"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("target")))
	reply.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	server.push(reply.ToBytes())
	deadline := time.Now().Add(time.Second)
	for targetClient.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if targetClient.writeCount() != 1 {
		t.Fatalf("mismatched Interface-ID target writes=%d, want 1", targetClient.writeCount())
	}
	if relay.repliesDroppedIID.Load() != 0 {
		t.Fatalf("mismatched Interface-ID owner drops=%d, want 0 after dispatch", relay.repliesDroppedIID.Load())
	}
	cancel()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mismatched-IID server loop did not stop")
	}
}

func TestDHCPv6ServerLoopRoutesSameInterfaceIDDifferentLink10198(t *testing.T) {
	server := newFakeConn()
	dispatcherServer := newFakeConn()
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) {
		return dispatcherServer, nil
	}
	targetClient := newFakeConn()
	targetRelay := &dhcpV6Relay{
		ifaceName:  "ll-same-id-target",
		kernelName: "lo",
		linkAddr:   net.ParseIP("2001:db8:60::1"),
	}
	targetAllowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 1), Port: 68}}
	_, release, err := dispatcher.register(context.Background(), targetRelay, targetClient, targetAllowed, []byte("shared"))
	if err != nil {
		t.Fatalf("register same-IID target: %v", err)
	}
	defer release()

	owner := &dhcpV6Relay{
		ifaceName: "gua-same-id-owner",
		linkAddr:  net.ParseIP("2001:db8:61::1"),
	}
	ownerAllowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 2), Port: 68}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&dhcpV6Manager{}).runDHCPV6ServerLoop(ctx, owner, server, newFakeConn(), ownerAllowed, []byte("shared"), dispatcher)
		close(done)
	}()
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    targetRelay.linkAddr,
		PeerAddr:    net.ParseIP("::1"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("shared")))
	reply.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	server.push(reply.ToBytes())
	deadline := time.Now().Add(time.Second)
	for targetClient.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if targetClient.writeCount() != 1 {
		t.Fatalf("same-IID different-LinkAddr target writes=%d, want 1", targetClient.writeCount())
	}
	if owner.repliesDroppedIID.Load() != 0 {
		t.Fatalf("same-IID different-LinkAddr owner drops=%d, want 0 after dispatch", owner.repliesDroppedIID.Load())
	}
	cancel()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("same-IID different-LinkAddr server loop did not stop")
	}
}

func TestDHCPv6ClientReplyDispatchRateLimited10198(t *testing.T) {
	client := newFakeDHCPV6Conn()
	client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort}
	upstream := newFakeConn()
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) {
		return upstream, nil
	}
	replyClient := newFakeConn()
	replyRelay := &dhcpV6Relay{
		ifaceName:  "ll-rate-reply",
		kernelName: "lo",
		linkAddr:   net.ParseIP("2001:db8:40::1"),
	}
	allowed := []*net.UDPAddr{{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort}}
	_, release, err := dispatcher.register(context.Background(), replyRelay, replyClient, allowed, []byte("ll-rate-reply"))
	if err != nil {
		t.Fatalf("register rate-limit reply target: %v", err)
	}
	defer release()

	m := newDHCPV6Manager()
	m.replyDispatcher = dispatcher
	m.now = func() time.Time { return time.Unix(123, 0) }
	relay := &dhcpV6Relay{
		ifaceName:     "ll-rate-client",
		kernelName:    "lo",
		linkAddr:      net.ParseIP("2001:db8:41::1"),
		maxPacketRate: 1,
	}
	server := newFakeConn()
	servers := []*net.UDPAddr{{IP: net.ParseIP("2001:db8:42::1"), Port: dhcpv6RelayPort}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.runDHCPV6ClientLoop(ctx, relay, client, server, relay.linkAddr, servers, nil)
		close(done)
	}()

	inner := newDHCPV6TestMessage(t)
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    replyRelay.linkAddr,
		PeerAddr:    net.ParseIP("::1"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ll-rate-reply")))
	reply.AddOption(dhcpv6.OptRelayMessage(inner))
	for range 8 {
		client.push(reply.ToBytes())
	}
	deadline := time.Now().Add(time.Second)
	for replyClient.writeCount()+int(relay.requestsDroppedRateLimit.Load()) < 8 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := replyClient.writeCount() + int(relay.requestsDroppedRateLimit.Load()); got != 8 {
		t.Fatalf("client Relay-Reply processing=%d, want 8 (writes=%d drops=%d)", got, replyClient.writeCount(), relay.requestsDroppedRateLimit.Load())
	}
	wantWrites := relayBurstFor(relay.maxPacketRate)
	if got := replyClient.writeCount(); got != wantWrites {
		t.Fatalf("client Relay-Reply writes=%d, want burst %d", got, wantWrites)
	}
	if got := relay.requestsDroppedRateLimit.Load(); got != uint64(8-wantWrites) {
		t.Fatalf("client Relay-Reply rate-limit drops=%d, want %d", got, 8-wantWrites)
	}
	cancel()
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rate-limit client loop did not stop")
	}
}

func TestDHCPv6ReplyDispatcherRestartsDeadServer10198(t *testing.T) {
	dead := newFakeConn()
	dead.readErr = errors.New("dead upstream socket")
	replacement := newFakeConn()
	var factoryCalls atomic.Int32
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) {
		if factoryCalls.Add(1) == 1 {
			return dead, nil
		}
		return replacement, nil
	}

	client := newFakeConn()
	relay := &dhcpV6Relay{ifaceName: "ll-restart", kernelName: "lo"}
	allowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 1), Port: 68}}
	server, release, err := dispatcher.register(context.Background(), relay, client, allowed, []byte("ll-restart"))
	if err != nil {
		t.Fatalf("register dispatcher target: %v", err)
	}
	defer release()

	deadline := time.Now().Add(time.Second)
	for (factoryCalls.Load() < 2 || replacement.readCalls.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if factoryCalls.Load() < 2 {
		t.Fatalf("dispatcher did not reopen after dead server (factory calls=%d)", factoryCalls.Load())
	}
	if replacement.readCalls.Load() == 0 {
		t.Fatal("dispatcher did not read from replacement server")
	}
	if _, err := server.WriteTo([]byte("probe"), allowed[0]); err != nil {
		t.Fatalf("existing target write after server restart: %v", err)
	}
	if replacement.writeCount() != 1 {
		t.Fatalf("replacement server writes=%d, want 1 after existing target restart", replacement.writeCount())
	}

	inner := newDHCPV6TestMessage(t)
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("::1"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ll-restart")))
	reply.AddOption(dhcpv6.OptRelayMessage(inner))
	replacement.srcAddr = allowed[0]
	replacement.push(reply.ToBytes())
	deadline = time.Now().Add(time.Second)
	for client.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.writeCount() != 1 {
		t.Fatalf("reply after server restart writes=%d, want 1", client.writeCount())
	}
	if got := client.firstWrite(t); !bytes.Equal(got, inner.ToBytes()) {
		t.Fatalf("reply after server restart payload = %x, want %x", got, inner.ToBytes())
	}
}

func TestDHCPv6ReplyDispatcherCancelsReopenOnRelease10198(t *testing.T) {
	dead := newFakeConn()
	dead.readErr = errors.New("dead upstream socket")
	reopenStarted := make(chan struct{})
	reopenCanceled := make(chan struct{})
	var factoryCalls atomic.Int32
	dispatcher := newDHCPV6ReplyDispatcher()
	dispatcher.newServer = func(ctx context.Context) (net.PacketConn, error) {
		if factoryCalls.Add(1) == 1 {
			return dead, nil
		}
		close(reopenStarted)
		<-ctx.Done()
		close(reopenCanceled)
		return nil, ctx.Err()
	}

	client := newFakeConn()
	relay := &dhcpV6Relay{ifaceName: "ll-cancel", kernelName: "lo"}
	allowed := []*net.UDPAddr{{IP: net.IPv4(10, 0, 0, 1), Port: 68}}
	_, release, err := dispatcher.register(context.Background(), relay, client, allowed, []byte("ll-cancel"))
	if err != nil {
		t.Fatalf("register dispatcher target: %v", err)
	}
	select {
	case <-reopenStarted:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not begin reopening after dead server")
	}
	release()
	select {
	case <-reopenCanceled:
	case <-time.After(time.Second):
		t.Fatal("dispatcher reopen did not observe final target release")
	}
}
