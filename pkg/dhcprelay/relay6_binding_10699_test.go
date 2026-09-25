package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

func TestPending6KeyBindsXIDDUIDAndIAType(t *testing.T) {
	request := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{1, 2, 3})
	key, ok := pending6KeyFor(request)
	if !ok {
		t.Fatal("pending6KeyFor rejected a valid client message")
	}

	advertise := *request
	advertise.MessageType = dhcpv6.MessageTypeAdvertise
	if got, ok := pending6KeyFor(&advertise); !ok || got != key {
		t.Fatalf("Solicit/Advertise keys = (%+v, %v), want (%+v, true)", got, ok, key)
	}

	differentXID := advertise
	differentXID.TransactionID = dhcpv6.TransactionID{1, 2, 4}
	if got, _ := pending6KeyFor(&differentXID); got == key {
		t.Fatal("different transaction ID matched the pending binding")
	}

	differentDUID := advertise
	differentDUID.Options.Options = append(dhcpv6.Options(nil), advertise.Options.Options...)
	differentDUID.Options.Del(dhcpv6.OptionClientID)
	differentDUID.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDUUID{UUID: [16]byte{1}}))
	if got, _ := pending6KeyFor(&differentDUID); got == key {
		t.Fatal("different client DUID matched the pending binding")
	}

	differentIAID := advertise
	differentIAID.Options.Options = append(dhcpv6.Options(nil), advertise.Options.Options...)
	differentIAID.Options.Del(dhcpv6.OptionIANA)
	differentIAID.AddOption(&dhcpv6.OptIANA{IaId: [4]byte{4, 3, 2, 1}})
	if got, _ := pending6KeyFor(&differentIAID); got == key {
		t.Fatal("different IAID matched the pending binding")
	}

	differentIAType := advertise
	differentIAType.Options.Options = append(dhcpv6.Options(nil), advertise.Options.Options...)
	differentIAType.Options.Del(dhcpv6.OptionIANA)
	differentIAType.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{1, 2, 3, 4}})
	if got, _ := pending6KeyFor(&differentIAType); got == key {
		t.Fatal("different IA type matched the pending binding")
	}
}

func TestPending6TableBoundedAndExpires(t *testing.T) {
	now := time.Unix(100, 0)
	table := newPendingTableOf[pending6Key](1, time.Second, func() time.Time { return now })
	first := pending6Key{xid: dhcpv6.TransactionID{1, 0, 0}}
	second := pending6Key{xid: dhcpv6.TransactionID{2, 0, 0}}
	table.insert(first)
	table.insert(second)
	if table.capacity() != 1 || table.occupancy() != 1 || table.evictions() != 1 {
		t.Fatalf("capacity/occupancy/evictions = %d/%d/%d, want 1/1/1",
			table.capacity(), table.occupancy(), table.evictions())
	}
	if table.matches(first) || !table.matches(second) {
		t.Fatal("capacity pressure did not retain only the newest binding")
	}
	now = now.Add(time.Second)
	if table.matches(second) || table.occupancy() != 0 {
		t.Fatal("expired DHCPv6 binding remained active")
	}
}

// TestDHCPV6RelayDropsUnboundServerReply is the #10699 fail-on-revert RED
// guard: restoring unconditional Relay-Reply forwarding reaches this client
// and leaves the no-request counter at zero, failing both assertions below.
func TestDHCPV6RelayDropsUnboundServerReply(t *testing.T) {
	relay := &dhcpV6Relay{
		ifaceName: "wan0",
		pending:   newPendingTableOf[pending6Key](4, pendingTTL, time.Now),
	}
	client := newFakeConn()
	defer client.Close()
	inner := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{7, 8, 9})
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    net.ParseIP("2001:db8:2::10"),
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte("wan0")))
	reply.AddOption(dhcpv6.OptRelayMessage(inner))
	server := &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}
	processDHCPV6ServerPacket(relay, client, reply, server,
		[]*net.UDPAddr{server}, []byte("wan0"))
	if client.writeCount() != 0 || relay.repliesForwarded.Load() != 0 {
		t.Fatalf("unbound reply reached client: writes=%d forwarded=%d",
			client.writeCount(), relay.repliesForwarded.Load())
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 1 {
		t.Fatalf("RepliesDroppedNoRequest = %d, want 1", got)
	}
}

func TestDHCPV6RelayPassesSolicitAdvertiseRequestReplyBindings(t *testing.T) {
	relay := &dhcpV6Relay{
		ifaceName:  "wan0",
		kernelName: "wan0",
		pending:    newPendingTableOf[pending6Key](8, pendingTTL, time.Now),
	}
	client := newFakeDHCPV6Conn()
	serverConn := newFakeConn()
	peer := net.ParseIP("2001:db8:2::10")
	link := net.ParseIP("2001:db8:1::1")
	server := &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}
	client.srcAddr = &net.UDPAddr{IP: peer, Port: dhcpv6ClientPort}

	manager := newDHCPV6Manager()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.runDHCPV6ClientLoop(ctx, relay, client, serverConn, link, []*net.UDPAddr{server}, nil)
		close(done)
	}()
	defer func() {
		cancel()
		_ = client.Close()
		_ = serverConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("DHCPv6 client loop did not stop")
		}
	}()

	forward := func(request *dhcpv6.Message, expectedWrites int) {
		t.Helper()
		key, ok := pending6KeyFor(request)
		if !ok {
			t.Fatal("could not key client request")
		}
		client.push(request.ToBytes())
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) && serverConn.writeCount() < expectedWrites {
			time.Sleep(time.Millisecond)
		}
		if got := serverConn.writeCount(); got != expectedWrites {
			t.Fatalf("forwarded client requests=%d, want %d", got, expectedWrites)
		}
		if !relay.pending.matches(key) {
			t.Fatal("forwarded request has no outstanding reply binding")
		}
	}
	reply := func(message *dhcpv6.Message) {
		t.Helper()
		outer := &dhcpv6.RelayMessage{
			MessageType: dhcpv6.MessageTypeRelayReply,
			HopCount:    1,
			LinkAddr:    link,
			PeerAddr:    peer,
		}
		outer.AddOption(dhcpv6.OptInterfaceID([]byte("wan0")))
		outer.AddOption(dhcpv6.OptRelayMessage(message))
		processDHCPV6ServerPacket(relay, client, outer, server,
			[]*net.UDPAddr{server}, []byte("wan0"))
	}

	solicit := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{1, 2, 3})
	forward(solicit, 1)
	advertise := *solicit
	advertise.MessageType = dhcpv6.MessageTypeAdvertise
	reply(&advertise)

	request := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{4, 5, 6})
	request.MessageType = dhcpv6.MessageTypeRequest
	forward(request, 2)
	response := *request
	response.MessageType = dhcpv6.MessageTypeReply
	reply(&response)

	if got := client.writeCount(); got != 2 {
		t.Fatalf("legitimate exchange client writes=%d, want 2", got)
	}
	if got := relay.requestsRelayed.Load(); got != 2 {
		t.Fatalf("forwarded request count=%d, want 2", got)
	}
	if got := relay.repliesForwarded.Load(); got != 2 {
		t.Fatalf("forwarded reply count=%d, want 2", got)
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 0 {
		t.Fatalf("RepliesDroppedNoRequest = %d, want 0", got)
	}
}
