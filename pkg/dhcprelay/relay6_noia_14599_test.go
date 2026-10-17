package dhcprelay

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// #14599 regression: RFC 8415 lets a server answer Confirm, Release, or
// Decline with a Reply that carries no IA at all — §18.3.3 (Confirm:
// Server ID, Client ID, and a Status Code, with no IA required),
// §18.3.7 (Release: a top-level Success Status Code, with an IA only
// carrying NoBinding), and §18.3.8 (Decline: the same shape as
// Release). Such a reply keys to (iaType 0, zero IAID) in
// pending6KeyFor, while the relayed request that carried an IA keyed
// to its lowest (iaType, IAID), so the IA-less Reply could never match
// and was dropped as RepliesDroppedNoRequest. The fix records an
// IA-less alias binding for exactly Confirm/Release/Decline (the
// request types whose Reply may legally omit every IA); every other
// request type keeps the strict IA-bound key, so an IA-less Reply to
// a recorded Solicit/Request is still dropped, and the #10699/#14181
// forged-reply bindings (peer, inner type, source) still apply on the
// alias path because the alias entry carries the same recorded client
// and request type.

var (
	relay14599Server = &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: dhcpv6RelayPort}
	relay14599Client = net.ParseIP("fe80::10")
	relay14599Peer   = net.ParseIP("2001:db8:1::1")
)

// relay14599Request builds a client request of the given type carrying
// the binding fixture's DUID and one IA_NA (IAID 1,2,3,4), so its
// pending key is IA-bound.
func relay14599Request(t *testing.T, msgType dhcpv6.MessageType, xid dhcpv6.TransactionID) *dhcpv6.Message {
	t.Helper()
	req := newDHCPV6BindingMessage(t, xid)
	req.MessageType = msgType
	return req
}

// relay14599IALessReply builds the RFC-shaped IA-less Reply answering
// req: same xid and Client ID, a Server ID, and only a top-level
// Status Code — no IA option of any kind.
func relay14599IALessReply(t *testing.T, req *dhcpv6.Message, status iana.StatusCode) *dhcpv6.Message {
	t.Helper()
	reply := &dhcpv6.Message{
		MessageType:   dhcpv6.MessageTypeReply,
		TransactionID: req.TransactionID,
	}
	reply.AddOption(dhcpv6.OptClientID(req.Options.ClientID()))
	reply.AddOption(dhcpv6.OptServerID(&dhcpv6.DUIDUUID{UUID: [16]byte{0x5e}}))
	reply.AddOption(&dhcpv6.OptStatusCode{StatusCode: status})
	return reply
}

// relay14599IAReply builds a Reply that echoes req's IA_NA, the shape
// a server uses for (among others) a Release/Decline NoBinding answer.
func relay14599IAReply(t *testing.T, req *dhcpv6.Message) *dhcpv6.Message {
	t.Helper()
	reply := *req
	reply.MessageType = dhcpv6.MessageTypeReply
	return &reply
}

func relay14599Relay() *dhcpV6Relay {
	return &dhcpV6Relay{
		ifaceName:  "wan0",
		kernelName: "wan0",
		pending:    newPendingTableOf[pending6Key, pending6Entry](8, pendingTTL, time.Now),
	}
}

func relay14599Deliver(relay *dhcpV6Relay, client *fakeConn, inner dhcpv6.DHCPv6, peer net.IP) {
	outer := &dhcpv6.RelayMessage{
		MessageType: dhcpv6.MessageTypeRelayReply,
		HopCount:    1,
		LinkAddr:    net.ParseIP("2001:db8:1::1"),
		PeerAddr:    peer,
	}
	outer.AddOption(dhcpv6.OptInterfaceID([]byte("wan0")))
	outer.AddOption(dhcpv6.OptRelayMessage(inner))
	processDHCPV6ServerPacket(relay, client, outer, relay14599Server,
		[]*net.UDPAddr{relay14599Server}, []byte("wan0"), false)
}

// TestRelayConfirmNotOnLinkIALessReplyForwarded14599 is the decisive
// probe row from the issue: a Confirm whose addresses are not on this
// link draws a NotOnLink Reply with no IA (§18.3.3). It must be
// forwarded exactly once, not dropped as unmatched.
func TestRelayConfirmNotOnLinkIALessReplyForwarded14599(t *testing.T) {
	relay := relay14599Relay()
	client := newFakeConn()
	defer client.Close()
	confirm := relay14599Request(t, dhcpv6.MessageTypeConfirm, dhcpv6.TransactionID{0x14, 0x59, 0x01})
	armDHCPV6ReplyFrom(t, relay, confirm, relay14599Client)

	reply := relay14599IALessReply(t, confirm, iana.StatusNotOnLink)
	relay14599Deliver(relay, client, reply, relay14599Client)

	if got := client.writeCount(); got != 1 {
		t.Fatalf("Confirm NotOnLink IA-less Reply client writes=%d want exactly 1", got)
	}
	if got := relay.repliesForwarded.Load(); got != 1 {
		t.Fatalf("RepliesForwarded=%d want 1", got)
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 0 {
		t.Fatalf("RepliesDroppedNoRequest=%d want 0 (legitimate reply mislabelled as unmatched)", got)
	}
}

// TestRelayReleaseSuccessIALessReplyForwarded14599 is the second
// decisive probe row: a Release whose leases were all bound draws a
// Success Reply with no IA (§18.3.7).
func TestRelayReleaseSuccessIALessReplyForwarded14599(t *testing.T) {
	relay := relay14599Relay()
	client := newFakeConn()
	defer client.Close()
	release := relay14599Request(t, dhcpv6.MessageTypeRelease, dhcpv6.TransactionID{0x14, 0x59, 0x02})
	armDHCPV6ReplyFrom(t, relay, release, relay14599Client)

	reply := relay14599IALessReply(t, release, iana.StatusSuccess)
	relay14599Deliver(relay, client, reply, relay14599Client)

	if got := client.writeCount(); got != 1 {
		t.Fatalf("Release Success IA-less Reply client writes=%d want exactly 1", got)
	}
	if got := relay.repliesForwarded.Load(); got != 1 {
		t.Fatalf("RepliesForwarded=%d want 1", got)
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 0 {
		t.Fatalf("RepliesDroppedNoRequest=%d want 0", got)
	}
}

// TestRelayDeclineSuccessIALessReplyForwarded14599 covers the third
// request type with the same Reply shape (§18.3.8).
func TestRelayDeclineSuccessIALessReplyForwarded14599(t *testing.T) {
	relay := relay14599Relay()
	client := newFakeConn()
	defer client.Close()
	decline := relay14599Request(t, dhcpv6.MessageTypeDecline, dhcpv6.TransactionID{0x14, 0x59, 0x03})
	armDHCPV6ReplyFrom(t, relay, decline, relay14599Client)

	reply := relay14599IALessReply(t, decline, iana.StatusSuccess)
	relay14599Deliver(relay, client, reply, relay14599Client)

	if got := client.writeCount(); got != 1 {
		t.Fatalf("Decline Success IA-less Reply client writes=%d want exactly 1", got)
	}
	if got := relay.repliesForwarded.Load(); got != 1 {
		t.Fatalf("RepliesForwarded=%d want 1", got)
	}
}

// TestRelayIALessReplyToSolicitOrRequestStillDropped14599 pins the
// acceptance boundary: the IA-less fallback must NOT widen to request
// types whose Reply is required to carry the IA. An IA-less Reply (or
// Advertise) answering a recorded Solicit or Request is still
// dropped, so the #10699 binding is not weakened.
func TestRelayIALessReplyToSolicitOrRequestStillDropped14599(t *testing.T) {
	cases := []struct {
		name    string
		request dhcpv6.MessageType
		inner   dhcpv6.MessageType
		xid     dhcpv6.TransactionID
	}{
		{"SolicitAdvertise", dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeAdvertise, dhcpv6.TransactionID{0x14, 0x59, 0x11}},
		{"SolicitReply", dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeReply, dhcpv6.TransactionID{0x14, 0x59, 0x12}},
		{"RequestReply", dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeReply, dhcpv6.TransactionID{0x14, 0x59, 0x13}},
		{"RenewReply", dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeReply, dhcpv6.TransactionID{0x14, 0x59, 0x14}},
		{"RebindReply", dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeReply, dhcpv6.TransactionID{0x14, 0x59, 0x15}},
		{"InformationRequestReply", dhcpv6.MessageTypeInformationRequest, dhcpv6.MessageTypeReply, dhcpv6.TransactionID{0x14, 0x59, 0x16}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := relay14599Relay()
			client := newFakeConn()
			defer client.Close()
			req := relay14599Request(t, tc.request, tc.xid)
			armDHCPV6ReplyFrom(t, relay, req, relay14599Client)

			reply := relay14599IALessReply(t, req, iana.StatusSuccess)
			reply.MessageType = tc.inner
			relay14599Deliver(relay, client, reply, relay14599Client)

			if got := client.writeCount(); got != 0 {
				t.Fatalf("IA-less %s to recorded %s was forwarded: writes=%d want 0", tc.inner, tc.request, got)
			}
			if got := relay.repliesForwarded.Load(); got != 0 {
				t.Fatalf("RepliesForwarded=%d want 0", got)
			}
		})
	}
}

// TestRelayReleaseIAEchoReplyStillForwarded14599 is the IA-echo
// control from the probe: a Reply that does carry the IA (e.g. a
// NoBinding IA, §18.3.7) matched before the fix and must keep
// matching through the original IA-bound key.
func TestRelayReleaseIAEchoReplyStillForwarded14599(t *testing.T) {
	relay := relay14599Relay()
	client := newFakeConn()
	defer client.Close()
	release := relay14599Request(t, dhcpv6.MessageTypeRelease, dhcpv6.TransactionID{0x14, 0x59, 0x21})
	armDHCPV6ReplyFrom(t, relay, release, relay14599Client)

	reply := relay14599IAReply(t, release)
	relay14599Deliver(relay, client, reply, relay14599Client)

	if got := client.writeCount(); got != 1 {
		t.Fatalf("Release IA-echo Reply client writes=%d want 1", got)
	}
	if got := relay.repliesDroppedNoRequest.Load(); got != 0 {
		t.Fatalf("RepliesDroppedNoRequest=%d want 0", got)
	}
}

// TestRelayConfirmIALessReplyForgedCellsStillDrop14599 pins that the
// alias path inherits every #10699/#14181 forged-reply check: wrong
// outer peer, wrong inner type, and an unrecorded transaction all
// still drop even though the reply is IA-less.
func TestRelayConfirmIALessReplyForgedCellsStillDrop14599(t *testing.T) {
	confirm := func(t *testing.T, relay *dhcpV6Relay) *dhcpv6.Message {
		t.Helper()
		req := relay14599Request(t, dhcpv6.MessageTypeConfirm, dhcpv6.TransactionID{0x14, 0x59, 0x31})
		armDHCPV6ReplyFrom(t, relay, req, relay14599Client)
		return req
	}

	t.Run("PeerMismatch", func(t *testing.T) {
		relay := relay14599Relay()
		client := newFakeConn()
		defer client.Close()
		req := confirm(t, relay)
		relay14599Deliver(relay, client, relay14599IALessReply(t, req, iana.StatusNotOnLink), relay14599Peer)
		if got := client.writeCount(); got != 0 {
			t.Fatalf("peer-mismatched IA-less Reply forwarded: writes=%d want 0", got)
		}
		if got := relay.repliesDroppedNoRequest.Load(); got != 1 {
			t.Fatalf("RepliesDroppedNoRequest=%d want 1", got)
		}
	})

	t.Run("WrongInnerType", func(t *testing.T) {
		relay := relay14599Relay()
		client := newFakeConn()
		defer client.Close()
		req := confirm(t, relay)
		adv := relay14599IALessReply(t, req, iana.StatusNotOnLink)
		adv.MessageType = dhcpv6.MessageTypeAdvertise
		relay14599Deliver(relay, client, adv, relay14599Client)
		if got := client.writeCount(); got != 0 {
			t.Fatalf("Advertise inner answering Confirm forwarded: writes=%d want 0", got)
		}
	})

	t.Run("UnrecordedTransaction", func(t *testing.T) {
		relay := relay14599Relay()
		client := newFakeConn()
		defer client.Close()
		req := relay14599Request(t, dhcpv6.MessageTypeConfirm, dhcpv6.TransactionID{0x14, 0x59, 0x32})
		// Deliberately NOT armed: no pending binding exists.
		relay14599Deliver(relay, client, relay14599IALessReply(t, req, iana.StatusNotOnLink), relay14599Client)
		if got := client.writeCount(); got != 0 {
			t.Fatalf("unrecorded IA-less Reply forwarded: writes=%d want 0", got)
		}
		if got := relay.repliesDroppedNoRequest.Load(); got != 1 {
			t.Fatalf("RepliesDroppedNoRequest=%d want 1", got)
		}
	})
}

// TestPending6IALessAliasOnlyForConfirmReleaseDecline14599 pins the
// key-level contract: after arming, the IA-less alias key resolves
// only for Confirm/Release/Decline, and the primary IA-bound key
// still distinguishes IAID and IA type (#10699).
func TestPending6IALessAliasOnlyForConfirmReleaseDecline14599(t *testing.T) {
	aliasKey := func(t *testing.T, req *dhcpv6.Message) pending6Key {
		t.Helper()
		reply := relay14599IALessReply(t, req, iana.StatusSuccess)
		key, ok := pending6KeyFor(reply)
		if !ok {
			t.Fatal("pending6KeyFor rejected IA-less reply")
		}
		if key.iaType != 0 || key.iaid != [4]byte{} {
			t.Fatalf("IA-less reply key = iaType %d iaid %v, want 0/[0 0 0 0]", key.iaType, key.iaid)
		}
		return key
	}

	for _, tc := range []struct {
		request dhcpv6.MessageType
		alias   bool
	}{
		{dhcpv6.MessageTypeConfirm, true},
		{dhcpv6.MessageTypeRelease, true},
		{dhcpv6.MessageTypeDecline, true},
		{dhcpv6.MessageTypeSolicit, false},
		{dhcpv6.MessageTypeRequest, false},
		{dhcpv6.MessageTypeRenew, false},
		{dhcpv6.MessageTypeRebind, false},
		{dhcpv6.MessageTypeInformationRequest, false},
	} {
		relay := relay14599Relay()
		req := relay14599Request(t, tc.request, dhcpv6.TransactionID{0x14, 0x59, 0x41})
		armDHCPV6ReplyFrom(t, relay, req, relay14599Client)
		if _, bound := relay.pending.lookup(aliasKey(t, req)); bound != tc.alias {
			t.Fatalf("%s: IA-less alias bound=%v want %v", tc.request, bound, tc.alias)
		}
	}
}
