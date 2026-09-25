package dhcprelay

import (
	"context"
	"errors"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/psaab/xpf/pkg/config"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakeDHCPV6Conn struct {
	*fakeConn
	joined bool
	left   bool
	iface  *net.Interface
	group  *net.UDPAddr
}

func newFakeDHCPV6Conn() *fakeDHCPV6Conn {
	return &fakeDHCPV6Conn{fakeConn: newFakeConn()}
}

func (c *fakeDHCPV6Conn) JoinGroup(iface *net.Interface, group *net.UDPAddr) error {
	c.joined = true
	c.iface = iface
	c.group = group
	return nil
}

func (c *fakeDHCPV6Conn) LeaveGroup(iface *net.Interface, group *net.UDPAddr) error {
	c.left = true
	return nil
}

func newDHCPV6TestMessage(t *testing.T) dhcpv6.DHCPv6 {
	t.Helper()
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	return msg
}

func newDHCPV6BindingMessage(t *testing.T, xid dhcpv6.TransactionID) *dhcpv6.Message {
	t.Helper()
	message := newDHCPV6TestMessage(t).(*dhcpv6.Message)
	message.TransactionID = xid
	message.MessageType = dhcpv6.MessageTypeSolicit
	message.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDUUID{
		UUID: [16]byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
			0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f},
	}))
	message.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{1, 2, 3, 4}})
	return message
}

func armDHCPV6Reply(t *testing.T, relay *dhcpV6Relay, message dhcpv6.DHCPv6) {
	t.Helper()
	if relay.pending == nil {
		relay.pending = newPendingTableOf[pending6Key](64, pendingTTL, time.Now)
	}
	key, ok := pending6KeyFor(message)
	if !ok {
		t.Fatal("failed to create DHCPv6 pending key")
	}
	relay.pending.insert(key)
}

func TestBuildRelayForwardV6RFC8415(t *testing.T) {
	msg := newDHCPV6TestMessage(t)
	link := net.ParseIP("2001:db8:1::1")
	peer := net.ParseIP("fe80::2")
	relay, err := buildRelayForwardV6(msg, link, peer, []byte("ge-0/0/0.0"))
	if err != nil {
		t.Fatalf("buildRelayForwardV6: %v", err)
	}
	if relay.Type() != dhcpv6.MessageTypeRelayForward || relay.HopCount != 0 {
		t.Fatalf("Relay-Forw header = type %v hop %d, want type 12 hop 0", relay.Type(), relay.HopCount)
	}
	if !relay.LinkAddr.Equal(link) || !relay.PeerAddr.Equal(peer) {
		t.Fatalf("Relay-Forw addresses = link %v peer %v, want %v %v", relay.LinkAddr, relay.PeerAddr, link, peer)
	}
	if got := string(relay.Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("Interface-ID = %q, want authored interface", got)
	}
	inner := relay.Options.RelayMessage()
	if inner == nil || inner.Type() != msg.Type() {
		t.Fatalf("Relay Message option did not preserve inner %v: %v", msg.Type(), inner)
	}
}

func TestBuildRelayForwardV6NestedGlobalSourceUsesUnspecifiedLink(t *testing.T) {
	msg := newDHCPV6TestMessage(t)
	interfaceLink := net.ParseIP("2001:db8:1::1")
	downstreamPeer := net.ParseIP("fe80::2")
	nested, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward, interfaceLink, downstreamPeer)
	if err != nil {
		t.Fatalf("EncapsulateRelay: %v", err)
	}

	globalSource := net.ParseIP("2001:db8:2::9")
	outerLink := relayForwardV6LinkAddress(interfaceLink, globalSource, true)
	if !outerLink.IsUnspecified() {
		t.Fatalf("nested global source link-address = %v, want ::", outerLink)
	}
	outer, err := buildRelayForwardV6(nested, outerLink, globalSource, nil)
	if err != nil {
		t.Fatalf("build nested Relay-Forw: %v", err)
	}
	if !outer.LinkAddr.IsUnspecified() {
		t.Fatalf("nested global-source Relay-Forw link-address = %v, want ::", outer.LinkAddr)
	}

	linkLocalSource := net.ParseIP("fe80::9")
	if got := relayForwardV6LinkAddress(interfaceLink, linkLocalSource, true); !got.Equal(interfaceLink) {
		t.Fatalf("nested link-local source link-address = %v, want %v", got, interfaceLink)
	}
	if got := relayForwardV6LinkAddress(interfaceLink, globalSource, false); !got.Equal(interfaceLink) {
		t.Fatalf("client global source link-address = %v, want %v", got, interfaceLink)
	}
}
func TestDHCPV6InterfaceIDOverrideAndDefault(t *testing.T) {
	if got := string(effectiveDHCPv6InterfaceID("", "ge-0/0/0.0")); got != "ge-0/0/0.0" {
		t.Fatalf("default Interface-ID = %q, want authored interface", got)
	}
	if got := string(effectiveDHCPv6InterfaceID("circuit-42", "ge-0/0/0.0")); got != "circuit-42" {
		t.Fatalf("override Interface-ID = %q, want circuit-42", got)
	}
	cfg := &config.DHCPRelayV6Config{
		InterfaceIDOverride: "global-iid",
		ServerGroups: map[string]*config.DHCPRelayV6ServerGroup{
			"sg6": {Name: "sg6", Servers: []string{"2001:db8::5"}},
		},
		Groups: map[string]*config.DHCPRelayV6Group{
			"g6": {Name: "g6", Interfaces: []string{"ge-0/0/0.0"}, ActiveServerGroup: "sg6"},
			"g7": {Name: "g7", Interfaces: []string{"ge-0/0/1.0"}, ActiveServerGroup: "sg6", InterfaceIDOverride: "group-iid"},
			"g8": {Name: "g8", Interfaces: []string{"ge-0/0/2.0"}, ActiveServerGroup: "sg6", InterfaceIDOverrideSet: true},
		},
	}
	desired := computeDHCPV6Desired(cfg, nil)
	if got := desired["ge-0/0/0.0"].spec.interfaceID; got != "global-iid" {
		t.Fatalf("global Interface-ID inheritance = %q, want global-iid", got)
	}
	if got := desired["ge-0/0/1.0"].spec.interfaceID; got != "group-iid" {
		t.Fatalf("group Interface-ID precedence = %q, want group-iid", got)
	}
	explicitDefault := desired["ge-0/0/2.0"]
	if explicitDefault.spec.interfaceID != "" {
		t.Fatalf("explicit group-default stored Interface-ID = %q, want empty sentinel", explicitDefault.spec.interfaceID)
	}
	if got := string(effectiveDHCPv6InterfaceID(explicitDefault.spec.interfaceID, explicitDefault.ifaceName)); got != "ge-0/0/2.0" {
		t.Fatalf("explicit group-default Interface-ID = %q, want authored interface", got)
	}
}

func TestBuildRelayForwardV6HopLimit(t *testing.T) {
	msg := newDHCPV6TestMessage(t)
	link := net.ParseIP("2001:db8:1::1")
	peer := net.ParseIP("fe80::2")
	upstream, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward, link, peer)
	if err != nil {
		t.Fatalf("EncapsulateRelay: %v", err)
	}
	upstream.HopCount = dhcpv6MaxHopCount - 1
	forward, err := buildRelayForwardV6(upstream, link, peer, nil)
	if err != nil || forward.HopCount != dhcpv6MaxHopCount {
		t.Fatalf("hop 7 should forward as hop 8: relay=%v err=%v", forward, err)
	}
	upstream.HopCount = dhcpv6MaxHopCount
	if _, err := buildRelayForwardV6(upstream, link, peer, nil); err == nil {
		t.Fatal("hop 8 must be dropped before creating hop 9")
	}
	reply, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayReply, link, peer)
	if err != nil {
		t.Fatalf("EncapsulateRelay reply: %v", err)
	}
	reply.HopCount = dhcpv6MaxHopCount
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	if _, _, err := decapsulateRelayReplyV6(reply, []byte("ge-0/0/0.0")); err != nil {
		t.Fatalf("Relay-Reply hop 8 should be accepted: %v", err)
	}
	reply.HopCount = dhcpv6MaxHopCount + 1
	if _, _, err := decapsulateRelayReplyV6(reply, []byte("ge-0/0/0.0")); err == nil {
		t.Fatal("Relay-Reply hop 9 must be dropped at the boundary")
	}
	malformed := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayForward,
		HopCount:    1,
		LinkAddr:    link,
		PeerAddr:    peer,
	}
	if _, err := buildRelayForwardV6(malformed, link, peer, nil); err == nil {
		t.Fatal("Relay-Forw with a missing nested Relay Message must be dropped")
	}
}

func TestDecapsulateRelayReplyV6(t *testing.T) {
	msg := newDHCPV6TestMessage(t)
	peer := net.ParseIP("fe80::20")
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    peer,
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	reply.AddOption(dhcpv6.OptRelayMessage(msg))
	inner, dst, err := decapsulateRelayReplyV6(reply, []byte("ge-0/0/0.0"))
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if inner.Type() != msg.Type() || dst.Port != dhcpv6ClientPort || !dst.IP.Equal(peer) {
		t.Fatalf("decapsulated inner/destination = %v/%v, want %v/%d", inner.Type(), dst, msg.Type(), dhcpv6ClientPort)
	}

	nested := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    0,
		LinkAddr:    net.ParseIP("2001:db8:2::1"),
		PeerAddr:    net.ParseIP("fe80::30"),
	}
	nested.AddOption(dhcpv6.OptRelayMessage(msg))
	outer := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:3::1"),
		PeerAddr:    peer,
	}
	outer.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	outer.AddOption(dhcpv6.OptRelayMessage(nested))
	inner, dst, err = decapsulateRelayReplyV6(outer, []byte("ge-0/0/0.0"))
	if err != nil {
		t.Fatalf("nested decapsulate: %v", err)
	}
	if inner.Type() != dhcpv6.MessageTypeRelayReply || dst.Port != dhcpv6RelayPort || !dst.IP.Equal(peer) {
		t.Fatalf("nested inner/destination = %v/%v, want Relay-Reply/%d", inner.Type(), dst, dhcpv6RelayPort)
	}

	malformed := &dhcpv6.RelayMessage{MessageType: dhcpv6.MessageTypeRelayReply, PeerAddr: peer}
	if _, _, err := decapsulateRelayReplyV6(malformed, nil); err == nil {
		t.Fatal("Relay-Reply without Relay Message option must be dropped")
	}
}

func TestDecapsulateRelayReplyV6InterfaceID(t *testing.T) {
	msg := newDHCPV6TestMessage(t)
	peer := net.ParseIP("fe80::20")
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		PeerAddr:    peer,
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	reply.AddOption(dhcpv6.OptRelayMessage(msg))
	if _, _, err := decapsulateRelayReplyV6(reply, []byte("ge-0/0/0.0")); err != nil {
		t.Fatalf("matching Interface-ID rejected: %v", err)
	}
	absent := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		PeerAddr:    peer,
	}
	absent.AddOption(dhcpv6.OptRelayMessage(msg))
	if _, _, err := decapsulateRelayReplyV6(absent, []byte("ge-0/0/0.0")); err == nil {
		t.Fatal("Relay-Reply without Interface-ID must be dropped")
	}
	if _, _, err := decapsulateRelayReplyV6(reply, []byte("ge-0/0/1.0")); err == nil {
		t.Fatal("mismatched Interface-ID must be dropped")
	}
}

func TestDHCPV6ManagerWiresSocketsAndHAGate(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	factoryReady := make(chan struct{})
	m := NewManager()
	m.v6.resolveLink = func(string) (net.IP, error) {
		return net.ParseIP("2001:db8:1::1"), nil
	}
	m.v6.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort, Zone: name}
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		if err := client.JoinGroup(client.iface, client.group); err != nil {
			return dhcpV6Sockets{}, err
		}
		close(factoryReady)
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	m.SetMasterGate(func(string) bool { return false })
	cfg := &config.DHCPRelayConfig{V6: &config.DHCPRelayV6Config{
		ServerGroups: map[string]*config.DHCPRelayV6ServerGroup{
			"sg6": {Name: "sg6", Servers: []string{"2001:db8::5"}},
		},
		Groups: map[string]*config.DHCPRelayV6Group{
			"g6": {Name: "g6", Interfaces: []string{"ge-0/0/0.0"}, ActiveServerGroup: "sg6"},
		},
	}}
	m.Apply(context.Background(), cfg)
	<-factoryReady
	if !client.joined || !client.group.IP.Equal(net.ParseIP(dhcpv6RelayMulticast)) {
		t.Fatalf("client socket multicast membership = joined:%v group:%v", client.joined, client.group)
	}
	client.push(newDHCPV6TestMessage(t).ToBytes())
	time.Sleep(20 * time.Millisecond)
	if got := server.writeCount(); got != 0 {
		t.Fatalf("HA backup forwarded %d DHCPv6 requests", got)
	}
	m.Stop()
	if !client.left {
		t.Fatal("stopping DHCPv6 relay must leave ff02::1:2")
	}

	// A master on the same socket must relay to UDP/547, not the client port.
	client = newFakeDHCPV6Conn()
	server = newFakeConn()
	m = NewManager()
	m.v6.resolveLink = func(string) (net.IP, error) { return net.ParseIP("2001:db8:1::1"), nil }
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
	m.Apply(context.Background(), cfg)
	request := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{1, 2, 3})
	client.push(request.ToBytes())
	deadline := time.Now().Add(time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() != 1 {
		t.Fatalf("HA master did not forward DHCPv6 request, writes=%d", server.writeCount())
	}
	server.mu.Lock()
	destination := server.writes[0].addr.(*net.UDPAddr)
	server.mu.Unlock()
	if destination.Port != dhcpv6RelayPort || !destination.IP.Equal(net.ParseIP("2001:db8::5")) {
		t.Fatalf("upstream destination = %v, want [2001:db8::5]:547", destination)
	}
	forward, err := dhcpv6.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("parse forwarded request: %v", err)
	}
	if got := string(forward.(*dhcpv6.RelayMessage).Options.InterfaceID()); got != "ge-0/0/0.0" {
		t.Fatalf("default Interface-ID on live path = %q", got)
	}
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	replyInner := *request
	replyInner.MessageType = dhcpv6.MessageTypeAdvertise
	reply.AddOption(dhcpv6.OptRelayMessage(&replyInner))
	pushServer := func(source *net.UDPAddr, data []byte) {
		server.mu.Lock()
		server.srcAddr = source
		server.mu.Unlock()
		server.push(data)
		drainDeadline := time.Now().Add(time.Second)
		for time.Now().Before(drainDeadline) {
			server.mu.Lock()
			pending := len(server.pending)
			server.mu.Unlock()
			if pending == 0 {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("server test packet was not consumed")
	}
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}, reply.ToBytes())
	deadline = time.Now().Add(time.Second)
	for client.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.writeCount() != 1 {
		t.Fatalf("DHCPv6 Relay-Reply was not forwarded to client, writes=%d", client.writeCount())
	}
	client.mu.Lock()
	clientDestination := client.writes[0].addr.(*net.UDPAddr)
	client.mu.Unlock()
	if clientDestination.Port != dhcpv6ClientPort || !clientDestination.IP.Equal(net.ParseIP("fe80::2")) || clientDestination.Zone != "ge-0/0/0.0" {
		t.Fatalf("client destination = %v, want fe80::2%%ge-0/0/0.0:546", clientDestination)
	}
	stats := m.Stats()
	var v6Stats *RelayStats
	for i := range stats {
		if stats[i].Family == "inet6" {
			v6Stats = &stats[i]
			break
		}
	}
	if v6Stats == nil || v6Stats.RequestsRelayed != 1 || v6Stats.RepliesForwarded != 1 ||
		v6Stats.PendingSize != 1 || v6Stats.RepliesDroppedNoRequest != 0 {
		t.Fatalf("DHCPv6 stats row = %+v, want one request/reply, one pending binding, and no unbound drops", v6Stats)
	}

	missingIID := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}
	missingIID.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	mismatchedIID := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}
	mismatchedIID.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/1.0")))
	mismatchedIID.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))

	baseline := client.writeCount()
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}, missingIID.ToBytes())
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}, mismatchedIID.ToBytes())
	if got := client.writeCount(); got != baseline {
		t.Fatalf("missing/mismatched Interface-ID replies reached client: writes=%d baseline=%d", got, baseline)
	}

	baseline = client.writeCount()
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::99"), Port: dhcpv6RelayPort}, reply.ToBytes())
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6ClientPort}, reply.ToBytes())
	malformedNested := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    0,
		LinkAddr:    net.ParseIP("2001:db8:2::1"),
		PeerAddr:    net.ParseIP("fe80::3"),
	}
	malformedOuter := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}
	malformedOuter.AddOption(dhcpv6.OptRelayMessage(malformedNested))
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}, malformedOuter.ToBytes())
	time.Sleep(30 * time.Millisecond)
	if got := client.writeCount(); got != baseline {
		t.Fatalf("invalid DHCPv6 replies reached client: writes=%d baseline=%d", got, baseline)
	}
	m.v6.mu.Lock()
	var liveRelay *dhcpV6Relay
	if current := m.v6.relays["ge-0/0/0.0"]; current != nil {
		liveRelay = current
	}
	m.v6.mu.Unlock()
	if liveRelay == nil {
		t.Fatal("DHCPv6 relay disappeared before nested-reply test")
	}
	nestedDropsBefore := liveRelay.repliesDroppedNested.Load()
	nestedInner := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    0,
		LinkAddr:    net.ParseIP("2001:db8:2::1"),
		PeerAddr:    net.ParseIP("fe80::3"),
	}
	nestedInner.AddOption(dhcpv6.OptRelayMessage(newDHCPV6TestMessage(t)))
	validNested := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("fe80::2"),
	}
	validNested.AddOption(dhcpv6.OptInterfaceID([]byte("ge-0/0/0.0")))
	validNested.AddOption(dhcpv6.OptRelayMessage(nestedInner))
	pushServer(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}, validNested.ToBytes())
	deadline = time.Now().Add(time.Second)
	for liveRelay.repliesDroppedNested.Load() == nestedDropsBefore && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := liveRelay.repliesDroppedNested.Load(); got != nestedDropsBefore+1 {
		t.Fatalf("valid nested DHCPv6 reply drops=%d, want %d", got, nestedDropsBefore+1)
	}
	if got := client.writeCount(); got != baseline {
		t.Fatalf("valid nested DHCPv6 reply reached client: writes=%d baseline=%d", got, baseline)
	}

	m.Stop()
}
func TestDHCPV6ClientRateLimitCountsFloodDrops(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6ClientPort}
	now := time.Unix(123, 0)
	m := newDHCPV6Manager()
	m.now = func() time.Time { return now }
	relay := &dhcpV6Relay{
		ifaceName:     "ge-0/0/0.0",
		kernelName:    "ge-0/0/0.0",
		maxPacketRate: 1,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	message := newDHCPV6TestMessage(t).ToBytes()
	go func() {
		m.runDHCPV6ClientLoop(ctx, relay, client, server, net.ParseIP("2001:db8:1::1"),
			[]*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()
	for range 4 {
		client.push(message)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && server.writeCount()+int(relay.requestsDroppedRateLimit.Load()) < 4 {
		time.Sleep(time.Millisecond)
	}
	if got := server.writeCount(); got != relayBurstFor(1) {
		t.Fatalf("rate-limited DHCPv6 writes=%d, want burst %d", got, relayBurstFor(1))
	}
	if got := relay.requestsDroppedRateLimit.Load(); got != uint64(4-relayBurstFor(1)) {
		t.Fatalf("rate-limited DHCPv6 drops=%d, want %d", got, 4-relayBurstFor(1))
	}
	cancel()
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rate-limited client loop did not stop")
	}
}

func TestDHCPV6ClientDropsNestedRelayByDefault(t *testing.T) {
	client := newFakeDHCPV6Conn()
	server := newFakeConn()
	client.srcAddr = &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6RelayPort}
	inner := newDHCPV6TestMessage(t)
	nested, err := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward,
		net.ParseIP("2001:db8:1::1"), net.ParseIP("2001:db8:2::1"))
	if err != nil {
		t.Fatalf("EncapsulateRelay nested: %v", err)
	}
	m := newDHCPV6Manager()
	relay := &dhcpV6Relay{ifaceName: "ge-0/0/0.0", kernelName: "ge-0/0/0.0", maxPacketRate: 100}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.runDHCPV6ClientLoop(ctx, relay, client, server, net.ParseIP("2001:db8:1::1"),
			[]*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()
	client.push(nested.ToBytes())
	deadline := time.Now().Add(time.Second)
	for relay.requestsDroppedNested.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := relay.requestsDroppedNested.Load(); got != 1 {
		t.Fatalf("nested DHCPv6 drops=%d, want 1", got)
	}
	if got := server.writeCount(); got != 0 {
		t.Fatalf("nested DHCPv6 request reached upstream: writes=%d", got)
	}
	cancel()
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nested-drop client loop did not stop")
	}
}

func TestDHCPV6RunRebuildsOnAddressOrIfindexDrift(t *testing.T) {
	var attempts atomic.Int32
	var ifindexCalls atomic.Int32
	firstStarted := make(chan struct{}, 1)
	secondStarted := make(chan struct{}, 1)
	var firstClient *fakeDHCPV6Conn
	var firstServer *fakeConn
	var secondClient *fakeDHCPV6Conn
	var secondServer *fakeConn
	m := newDHCPV6Manager()
	m.retryInterval = time.Millisecond
	m.ifindexCheck = time.Millisecond
	m.resolveLink = func(string) (net.IP, error) {
		return net.ParseIP("2001:db8:1::1"), nil
	}
	m.resolveIfindex = func(string) (int, error) {
		switch ifindexCalls.Add(1) {
		case 1:
			return 0, errors.New("ifindex lookup transiently unavailable")
		case 2:
			return 1, nil
		default:
			return 2, nil
		}
	}
	m.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		client := newFakeDHCPV6Conn()
		server := newFakeConn()
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		if attempts.Add(1) == 1 {
			firstClient, firstServer = client, server
			firstStarted <- struct{}{}
		} else {
			secondClient, secondServer = client, server
			secondStarted <- struct{}{}
		}
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	relay := &dhcpV6Relay{ifaceName: "ge-0/0/0.0", kernelName: "ge-0/0/0.0"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.run(relay, ctx, []*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("v6 drift test did not start first session")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("v6 drift did not rebuild the session")
	}
	if !firstClient.isClosed() || !firstServer.isClosed() {
		t.Fatal("stale v6 sockets remained open after identity drift")
	}
	if secondClient.isClosed() || secondServer.isClosed() {
		t.Fatal("rebuilt v6 sockets were closed immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("v6 drift supervisor did not stop")
	}
	if !secondClient.isClosed() || !secondServer.isClosed() {
		t.Fatal("rebuilt v6 sockets were not closed on cancellation")
	}
}
func TestDHCPV6RunRetriesOneSidedSessionError(t *testing.T) {
	var attempts atomic.Int32
	secondStarted := make(chan struct{}, 1)
	var successfulClient *fakeDHCPV6Conn
	var successfulServer *fakeConn
	m := newDHCPV6Manager()
	m.retryInterval = time.Millisecond
	m.resolveLink = func(string) (net.IP, error) {
		return net.ParseIP("2001:db8:1::1"), nil
	}
	m.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		attempt := attempts.Add(1)
		client := newFakeDHCPV6Conn()
		server := newFakeConn()
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		if attempt == 1 {
			server.readErr = errors.New("upstream socket failed")
		} else {
			successfulClient = client
			successfulServer = server
			secondStarted <- struct{}{}
		}
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	relay := &dhcpV6Relay{ifaceName: "ge-0/0/0.0", kernelName: "ge-0/0/0.0"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.run(relay, ctx, []*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("v6 supervisor did not retry after one-sided session failure")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("v6 session attempts=%d, want 2 while recovered session is live", got)
	}
	if successfulClient == nil || successfulClient.isClosed() || successfulServer == nil || successfulServer.isClosed() {
		t.Fatal("successful retry session was already closed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("v6 supervisor did not stop promptly after cancellation")
	}
	if !successfulClient.isClosed() || !successfulServer.isClosed() {
		t.Fatal("successful retry sockets were not closed on cancellation")
	}
}
func TestDHCPV6RunRetriesStartupFailure(t *testing.T) {
	const failures = 3
	var attempts atomic.Int32
	ready := make(chan struct{}, 1)
	var firstClient *fakeDHCPV6Conn
	var firstServer *fakeConn
	var successfulClient *fakeDHCPV6Conn
	var successfulServer *fakeConn
	m := newDHCPV6Manager()
	m.retryInterval = time.Millisecond
	m.resolveLink = func(string) (net.IP, error) {
		return net.ParseIP("2001:db8:1::1"), nil
	}
	m.newConn = func(_ context.Context, name string, _ net.IP) (dhcpV6Sockets, error) {
		attempt := attempts.Add(1)
		client := newFakeDHCPV6Conn()
		server := newFakeConn()
		if attempt <= failures {
			if firstClient == nil {
				firstClient = client
				firstServer = server
			}
			return dhcpV6Sockets{client: client, server: server}, errors.New("interface not ready")
		}
		client.iface = &net.Interface{Name: name, Index: 1}
		client.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		successfulClient = client
		successfulServer = server
		ready <- struct{}{}
		return dhcpV6Sockets{client: client, server: server, iface: client.iface, group: client.group}, nil
	}
	relay := &dhcpV6Relay{ifaceName: "ge-0/0/0.0", kernelName: "ge-0/0/0.0"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		m.run(relay, ctx, []*net.UDPAddr{{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}}, nil)
		close(done)
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("v6 run did not recover from transient startup failures")
	}
	if got := attempts.Load(); got != failures+1 {
		t.Fatalf("v6 startup attempts=%d, want %d", got, failures+1)
	}
	if firstClient == nil || !firstClient.isClosed() || firstServer == nil || !firstServer.isClosed() {
		t.Fatal("partial startup sockets were not closed before retry")
	}
	if successfulClient == nil || successfulClient.isClosed() || successfulServer == nil || successfulServer.isClosed() {
		t.Fatal("successful startup session was already closed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("v6 run did not stop after startup recovery")
	}
	if !successfulClient.isClosed() || !successfulServer.isClosed() {
		t.Fatal("successful startup sockets were not closed on cancellation")
	}
}
