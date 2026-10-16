package dhcprelay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #14181 regression: a Relay-Reply must be bound to (a) the receiving
// interface (client-socket arrivals may select only that interface's own
// target), (b) the recorded soliciting client address (outer PeerAddr must
// match), and (c) a legitimate server inner type for the recorded request
// (never RECONFIGURE / client-direction types, never loopback peer).
// Each subtest fails on pre-fix master: PeerAddr was arbitrary unicast,
// inner type was unchecked, and the client loop dispatched by
// attacker-controlled Interface-ID to any target.

var (
	relay14181Server  = &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}
	relay14181ClientA = net.ParseIP("fe80::10")
	relay14181ClientB = net.ParseIP("fe80::20")
)

func relay14181Reply(t *testing.T, inner dhcpv6.DHCPv6, peer net.IP, iid string) *dhcpv6.RelayMessage {
	t.Helper()
	reply := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    peer,
	}
	reply.AddOption(dhcpv6.OptInterfaceID([]byte(iid)))
	reply.AddOption(dhcpv6.OptRelayMessage(inner))
	return reply
}

func relay14181Advertise(t *testing.T, req *dhcpv6.Message) *dhcpv6.Message {
	t.Helper()
	adv := *req
	adv.MessageType = dhcpv6.MessageTypeAdvertise
	// pending6KeyFor selects the first IA in sorted order; a shallow copy
	// shares options, which is exactly what a server echo looks like.
	return &adv
}

func TestRelayReplyPeerMismatchDropped14181(t *testing.T) {
	relay := &dhcpV6Relay{ifaceName: "wan0", kernelName: "wan0", pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	client := newFakeConn()
	defer client.Close()
	solicit := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{1, 2, 3})
	armDHCPV6ReplyFrom(t, relay, solicit, relay14181ClientA)

	// Pending tuple matches, server source is configured, but PeerAddr
	// names a different host than the soliciting client.
	reply := relay14181Reply(t, relay14181Advertise(t, solicit), relay14181ClientB, "wan0")
	processDHCPV6ServerPacket(relay, client, reply, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 0 || relay.repliesForwarded.Load() != 0 {
		t.Fatalf("peer-mismatched reply was forwarded: writes=%d forwarded=%d", client.writeCount(), relay.repliesForwarded.Load())
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 1 {
		t.Fatalf("RepliesDroppedNoRequest=%d want 1 for peer mismatch", got)
	}

	// Control: same pending tuple with the correct peer is forwarded.
	replyOK := relay14181Reply(t, relay14181Advertise(t, solicit), relay14181ClientA, "wan0")
	processDHCPV6ServerPacket(relay, client, replyOK, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 1 {
		t.Fatalf("correct-peer reply writes=%d want 1", client.writeCount())
	}
}

func TestRelayReplyLoopbackPeerDropped14181(t *testing.T) {
	relay := &dhcpV6Relay{ifaceName: "wan0", kernelName: "wan0", pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	client := newFakeConn()
	defer client.Close()
	solicit := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{4, 5, 6})
	armDHCPV6ReplyFrom(t, relay, solicit, relay14181ClientA)
	reply := relay14181Reply(t, relay14181Advertise(t, solicit), net.ParseIP("::1"), "wan0")
	processDHCPV6ServerPacket(relay, client, reply, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 0 {
		t.Fatalf("loopback-peer reply was forwarded: writes=%d", client.writeCount())
	}
}

func TestRelayReplyReconfigureInnerDropped14181(t *testing.T) {
	relay := &dhcpV6Relay{ifaceName: "wan0", kernelName: "wan0", pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	client := newFakeConn()
	defer client.Close()
	solicit := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{7, 8, 9})
	armDHCPV6ReplyFrom(t, relay, solicit, relay14181ClientA)

	reconf := *solicit
	reconf.MessageType = dhcpv6.MessageTypeReconfigure
	reply := relay14181Reply(t, &reconf, relay14181ClientA, "wan0")
	processDHCPV6ServerPacket(relay, client, reply, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 0 {
		t.Fatalf("RECONFIGURE inner was forwarded to client: writes=%d", client.writeCount())
	}
	if got := relay.repliesDroppedInvalid.Load(); got != 1 {
		t.Fatalf("RepliesDroppedInvalid=%d want 1 for RECONFIGURE", got)
	}

	// A Reply inner answering a Solicit is also the wrong answer type.
	wrong := *solicit
	wrong.MessageType = dhcpv6.MessageTypeReply
	reply2 := relay14181Reply(t, &wrong, relay14181ClientA, "wan0")
	processDHCPV6ServerPacket(relay, client, reply2, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 0 {
		t.Fatalf("Reply-to-Solicit inner was forwarded: writes=%d", client.writeCount())
	}
}

func TestRelayReplyRequestReplyPair14181(t *testing.T) {
	relay := &dhcpV6Relay{ifaceName: "wan0", kernelName: "wan0", pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	client := newFakeConn()
	defer client.Close()
	request := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{10, 11, 12})
	request.MessageType = dhcpv6.MessageTypeRequest
	armDHCPV6ReplyFrom(t, relay, request, relay14181ClientA)
	resp := *request
	resp.MessageType = dhcpv6.MessageTypeReply
	reply := relay14181Reply(t, &resp, relay14181ClientA, "wan0")
	processDHCPV6ServerPacket(relay, client, reply, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 1 {
		t.Fatalf("Request->Reply with matching peer writes=%d want 1", client.writeCount())
	}
	// Advertise answering a Request is not legitimate.
	adv := *request
	adv.MessageType = dhcpv6.MessageTypeAdvertise
	reply2 := relay14181Reply(t, &adv, relay14181ClientA, "wan0")
	processDHCPV6ServerPacket(relay, client, reply2, relay14181Server, []*net.UDPAddr{relay14181Server}, []byte("wan0"), false)
	if client.writeCount() != 1 {
		t.Fatalf("Advertise-to-Request was forwarded: writes=%d want still 1", client.writeCount())
	}
}

func TestClientSocketRelayReplyCannotSelectOtherInterface14181(t *testing.T) {
	dispatcher := newDHCPV6ReplyDispatcher()
	upstream := newFakeConn()
	dispatcher.newServer = func(context.Context) (net.PacketConn, error) { return upstream, nil }

	clientA := newFakeConn()
	clientB := newFakeConn()
	relayA := &dhcpV6Relay{ifaceName: "lan-a", kernelName: "lo", linkAddr: net.ParseIP("2001:db8:a::1"), pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	relayB := &dhcpV6Relay{ifaceName: "lan-b", kernelName: "lo", linkAddr: net.ParseIP("2001:db8:b::1"), pending: newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now)}
	allowedB := []*net.UDPAddr{relay14181Server}
	_, releaseA, err := dispatcher.register(context.Background(), relayA, clientA, []*net.UDPAddr{relay14181Server}, []byte("lan-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	_, releaseB, err := dispatcher.register(context.Background(), relayB, clientB, allowedB, []byte("lan-b"))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseB()

	// Pending transaction lives on B; attacker on A's client socket crafts
	// a Relay-Reply naming B's Interface-ID with a valid configured-server
	// source and B's pending tuple.
	solicitB := newDHCPV6BindingMessage(t, dhcpv6.TransactionID{21, 22, 23})
	armDHCPV6ReplyFrom(t, relayB, solicitB, relay14181ClientB)
	forged := relay14181Reply(t, relay14181Advertise(t, solicitB), relay14181ClientB, "lan-b")
	forged.LinkAddr = relayB.linkAddr

	if dispatcher.dispatchFromClientSocket(forged, relay14181Server, relayA) {
		t.Fatal("client-socket Relay-Reply from A selected target B")
	}
	if clientB.writeCount() != 0 {
		t.Fatalf("cross-interface forged reply reached B client: writes=%d", clientB.writeCount())
	}
	if got := dispatcher.droppedLocal.Load(); got != 1 {
		t.Fatalf("droppedLocal=%d want 1", got)
	}

	// Control: the same packet arriving on B's own client socket (the
	// link-local shared-return shape) is forwarded to B's client.
	if !dispatcher.dispatchFromClientSocket(forged, relay14181Server, relayB) {
		t.Fatal("own-interface client-socket Relay-Reply was refused")
	}
	if clientB.writeCount() != 1 {
		t.Fatalf("own-interface reply writes=%d want 1", clientB.writeCount())
	}

	// Control: upstream-socket dispatch to B still works.
	if !dispatcher.dispatch(forged, relay14181Server) {
		t.Fatal("upstream dispatch to B was refused")
	}
	if clientB.writeCount() != 2 {
		t.Fatalf("upstream reply writes=%d want 2", clientB.writeCount())
	}
}

func TestPending6EntrySurvivesAdopt14181(t *testing.T) {
	now := time.Unix(200, 0)
	clock := func() time.Time { return now }
	src := newPendingTableOf[pending6Key, pending6Entry](8, time.Minute, clock)
	key := pending6Key{xid: dhcpv6.TransactionID{9, 9, 9}}
	src.insertValue(key, pending6EntryFor(relay14181ClientA, dhcpv6.MessageTypeSolicit))
	dst := newPendingTableOf[pending6Key, pending6Entry](8, time.Minute, clock)
	dst.adopt(src.snapshot())
	entry, ok := dst.lookup(key)
	if !ok || !entry.clientIP().Equal(relay14181ClientA) || entry.requestType != dhcpv6.MessageTypeSolicit {
		t.Fatalf("adopted entry = %+v ok=%v, want client %v Solicit", entry, ok, relay14181ClientA)
	}
}
