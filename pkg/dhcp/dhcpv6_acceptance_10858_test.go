package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/insomniacslk/dhcp/iana"
)

func acceptanceV6DUID(last byte) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, last}}
}

func acceptanceV6Address(addr string) *dhcpv6.OptIAAddress {
	return &dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP(addr),
		PreferredLifetime: 300 * time.Second,
		ValidLifetime:     600 * time.Second,
	}
}

func acceptanceV6Reply(t *testing.T, opts ...dhcpv6.Option) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("create DHCPv6 reply: %v", err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	for _, opt := range opts {
		msg.AddOption(opt)
	}
	return msg
}

func TestV6AcquireRejectsWrongIAID10858(t *testing.T) {
	wantIAID := [4]byte{0, 0, 0, 1}
	wrongIA := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 2}}
	wrongIA.Options.Add(acceptanceV6Address("2001:db8::2"))
	msg := acceptanceV6Reply(t, wrongIA)

	got, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", msg, nil, &wantIAID, nil)
	if err == nil {
		t.Fatalf("wrong-IAID Reply accepted: result=%+v", got)
	}
	if got != nil {
		t.Fatalf("wrong-IAID Reply returned a partial result: %+v", got)
	}
}

func TestV6AcquireRejectsWrongIAPDIAID10858(t *testing.T) {
	wantIAID := [4]byte{0, 0, 0, 1}
	wrongIA := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 2}}
	wrongIA.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: 300 * time.Second,
		ValidLifetime:     600 * time.Second,
		Prefix:            &net.IPNet{IP: net.ParseIP("2001:db8:200::"), Mask: net.CIDRMask(64, 128)},
	})
	msg := acceptanceV6Reply(t, wrongIA)

	got, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", msg,
		&DHCPv6Options{IATypes: []string{"ia-pd"}}, nil, &wantIAID)
	if err == nil || got != nil {
		t.Fatalf("wrong IA_PD IAID accepted: result=%+v err=%v", got, err)
	}
}

func TestV6AcquireRejectsStatusWithStrayOptions10858(t *testing.T) {
	wantNA := [4]byte{0, 0, 0, 1}
	wantPD := [4]byte{0, 0, 0, 1}
	t.Run("message status", func(t *testing.T) {
		ia := &dhcpv6.OptIANA{IaId: wantNA}
		ia.Options.Add(acceptanceV6Address("2001:db8::3"))
		msg := acceptanceV6Reply(t,
			&dhcpv6.OptStatusCode{StatusCode: iana.StatusUnspecFail, StatusMessage: "failed"},
			ia,
		)
		got, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", msg, nil, &wantNA, nil)
		if err == nil || got != nil {
			t.Fatalf("message-level failure with stray IAADDR accepted: result=%+v err=%v", got, err)
		}
	})

	t.Run("IA_NA status", func(t *testing.T) {
		ia := &dhcpv6.OptIANA{IaId: wantNA}
		ia.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail, StatusMessage: "no addresses"})
		ia.Options.Add(acceptanceV6Address("2001:db8::4"))
		msg := acceptanceV6Reply(t, ia)
		got, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", msg, nil, &wantNA, nil)
		if err == nil || got != nil {
			t.Fatalf("NoAddrsAvail IA_NA with stray IAADDR accepted: result=%+v err=%v", got, err)
		}
	})

	t.Run("IA_PD status", func(t *testing.T) {
		iapd := &dhcpv6.OptIAPD{IaId: wantPD}
		iapd.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail, StatusMessage: "no prefixes"})
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 300 * time.Second,
			ValidLifetime:     600 * time.Second,
			Prefix:            &net.IPNet{IP: net.ParseIP("2001:db8:100::"), Mask: net.CIDRMask(64, 128)},
		})
		msg := acceptanceV6Reply(t, iapd)
		got, err := (&Manager{}).parseV6ReplyChecked(context.Background(), "wan0", msg,
			&DHCPv6Options{IATypes: []string{"ia-pd"}}, nil, &wantPD)
		if err == nil || got != nil {
			t.Fatalf("NoPrefixAvail IA_PD with stray IAPREFIX accepted: result=%+v err=%v", got, err)
		}
	})
}

func TestV6AdvertiseSelectionHonorsPreference10858(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	clientID := acceptanceV6DUID(1)
	iaID := v6IANAIAID(hw)
	solicit, err := dhcpv6.NewSolicit(hw, dhcpv6.WithClientID(clientID))
	if err != nil {
		t.Fatalf("create SOLICIT: %v", err)
	}
	newAdvertise := func(serverID dhcpv6.DUID, preference uint8, address string) *dhcpv6.Message {
		t.Helper()
		msg, err := dhcpv6.NewMessage(
			dhcpv6.WithClientID(clientID),
			dhcpv6.WithServerID(serverID),
			dhcpv6.WithIANA(*acceptanceV6Address(address)),
			dhcpv6.WithIAID(iaID),
			dhcpv6.WithOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionPreference, OptionData: []byte{preference}}),
		)
		if err != nil {
			t.Fatalf("create ADVERTISE: %v", err)
		}
		msg.MessageType = dhcpv6.MessageTypeAdvertise
		msg.TransactionID = solicit.TransactionID
		return msg
	}

	fastLow := newAdvertise(acceptanceV6DUID(2), 10, "2001:db8::10")
	slowHigh := newAdvertise(acceptanceV6DUID(3), 200, "2001:db8::20")
	if !v6AdvertiseMatches(solicit, fastLow) || !v6AdvertiseMatches(solicit, slowHigh) {
		t.Fatal("valid low- and high-preference Advertises must match the Solicit")
	}
	selected := v6SelectAdvertise([]*dhcpv6.Message{fastLow, slowHigh})
	if selected == nil || !sameDUID(selected.Options.ServerID(), slowHigh.Options.ServerID()) {
		t.Fatalf("selected Server ID = %v, want slower Preference-200 server %v", selected.Options.ServerID(), slowHigh.Options.ServerID())
	}
	got, ok := netip.AddrFromSlice(selected.Options.IANA()[0].Options.OneAddress().IPv6Addr)
	if !ok || got != netip.MustParseAddr("2001:db8::20") {
		t.Errorf("selected offer address = %v, want high-preference offer 2001:db8::20", got)
	}
}

func TestV6ReplyMatcherBindsClientServerIAIDAndStatus10858(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	clientID := acceptanceV6DUID(1)
	grantingServer := acceptanceV6DUID(2)
	otherServer := acceptanceV6DUID(3)
	req, err := dhcpv6.NewSolicit(hw, dhcpv6.WithClientID(clientID))
	if err != nil {
		t.Fatalf("create SOLICIT: %v", err)
	}
	validReply := func(client, server dhcpv6.DUID, iaid [4]byte, status *dhcpv6.OptStatusCode) *dhcpv6.Message {
		ia := &dhcpv6.OptIANA{IaId: iaid}
		if status != nil {
			ia.Options.Add(status)
		}
		ia.Options.Add(acceptanceV6Address("2001:db8::30"))
		msg, err := dhcpv6.NewMessage(dhcpv6.WithClientID(client), dhcpv6.WithServerID(server))
		if err != nil {
			t.Fatalf("create Reply: %v", err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply
		msg.TransactionID = req.TransactionID
		msg.AddOption(ia)
		return msg
	}
	if !v6ReplyMatches(req, validReply(clientID, grantingServer, v6IANAIAID(hw), nil), nil) {
		t.Fatal("valid rapid-commit Reply rejected")
	}
	for name, reply := range map[string]*dhcpv6.Message{
		"other server": validReply(clientID, otherServer, v6IANAIAID(hw), nil),
		"wrong client": validReply(otherServer, grantingServer, v6IANAIAID(hw), nil),
		"wrong IAID":   validReply(clientID, grantingServer, [4]byte{0, 0, 0, 2}, nil),
		"failed IA":    validReply(clientID, grantingServer, v6IANAIAID(hw), &dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail}),
	} {
		if v6ReplyMatches(req, reply, grantingServer) {
			t.Errorf("%s Reply accepted", name)
		}
	}
	if v6ReplyMatches(req, validReply(clientID, otherServer, v6IANAIAID(hw), nil), grantingServer) {
		t.Error("Request Reply from a server other than the selected Advertise was accepted")
	}
}

func TestV6StatelessMatcherRejectsErrorStatus10858(t *testing.T) {
	clientID := acceptanceV6DUID(1)
	serverID := acceptanceV6DUID(2)
	req, err := dhcpv6.NewMessage(dhcpv6.WithClientID(clientID))
	if err != nil {
		t.Fatalf("create Information-Request: %v", err)
	}
	req.MessageType = dhcpv6.MessageTypeInformationRequest
	response, err := dhcpv6.NewMessage(dhcpv6.WithClientID(clientID), dhcpv6.WithServerID(serverID))
	if err != nil {
		t.Fatalf("create Information-Reply: %v", err)
	}
	response.MessageType = dhcpv6.MessageTypeReply
	response.TransactionID = req.TransactionID
	matcher := v6StatelessMatcher(req)
	if !matcher(response) {
		t.Fatal("successful stateless Reply rejected")
	}
	response.AddOption(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNotConfigured})
	if matcher(response) {
		t.Fatal("stateless Reply with error StatusCode accepted")
	}
}

type acceptanceV6Datagram struct {
	data []byte
	from net.Addr
}

type preferencePacketConn struct {
	incoming chan acceptanceV6Datagram
	written  chan *dhcpv6.Message
	closed   chan struct{}
	close    sync.Once
}

func newPreferencePacketConn() *preferencePacketConn {
	return &preferencePacketConn{
		incoming: make(chan acceptanceV6Datagram, 4),
		written:  make(chan *dhcpv6.Message, 4),
		closed:   make(chan struct{}),
	}
}

func (c *preferencePacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.incoming:
		return copy(buf, packet.data), packet.from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *preferencePacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	parsed, err := dhcpv6.FromBytes(data)
	if err != nil {
		return 0, err
	}
	msg, ok := parsed.(*dhcpv6.Message)
	if !ok {
		return 0, errors.New("outbound packet was not a DHCPv6 message")
	}
	c.written <- msg
	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit:
		for _, offer := range []*dhcpv6.Message{
			acceptanceAdvertise(msg, acceptanceV6DUID(2), 10, "2001:db8::10"),
			acceptanceAdvertise(msg, acceptanceV6DUID(3), 200, "2001:db8::20"),
		} {
			c.incoming <- acceptanceV6Datagram{
				data: offer.ToBytes(),
				from: &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6.DefaultServerPort},
			}
		}
	case dhcpv6.MessageTypeRequest:
		reply, err := dhcpv6.NewMessage(
			dhcpv6.WithClientID(msg.Options.ClientID()),
			dhcpv6.WithServerID(msg.Options.ServerID()),
			dhcpv6.WithIANA(*acceptanceV6Address("2001:db8::50")),
			dhcpv6.WithIAID(msg.Options.OneIANA().IaId),
		)
		if err != nil {
			return 0, err
		}
		reply.MessageType = dhcpv6.MessageTypeReply
		reply.TransactionID = msg.TransactionID
		c.incoming <- acceptanceV6Datagram{
			data: reply.ToBytes(),
			from: &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: dhcpv6.DefaultServerPort},
		}
	default:
		return 0, errors.New("unexpected DHCPv6 outbound message")
	}
	return len(data), nil
}

func (c *preferencePacketConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return nil
}

func (*preferencePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv6loopback, Port: dhcpv6.DefaultClientPort}
}

func (*preferencePacketConn) SetDeadline(time.Time) error      { return nil }
func (*preferencePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*preferencePacketConn) SetWriteDeadline(time.Time) error { return nil }

func acceptanceAdvertise(req *dhcpv6.Message, serverID dhcpv6.DUID, preference uint8, address string) *dhcpv6.Message {
	adv, err := dhcpv6.NewMessage(
		dhcpv6.WithClientID(req.Options.ClientID()),
		dhcpv6.WithServerID(serverID),
		dhcpv6.WithIANA(*acceptanceV6Address(address)),
		dhcpv6.WithIAID(req.Options.OneIANA().IaId),
		dhcpv6.WithOption(&dhcpv6.OptionGeneric{
			OptionCode: dhcpv6.OptionPreference,
			OptionData: []byte{preference},
		}),
	)
	if err != nil {
		panic(err)
	}
	adv.MessageType = dhcpv6.MessageTypeAdvertise
	adv.TransactionID = req.TransactionID
	return adv
}

func TestV6AcquireCollectsAdvertisesAndBindsSelectedServer10858(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	conn := newPreferencePacketConn()
	client, err := nclient6.NewWithConn(conn, hw)
	if err != nil {
		t.Fatalf("create DHCPv6 client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := v6Acquire(ctx, client, []dhcpv6.Modifier{dhcpv6.WithClientID(acceptanceV6DUID(1))})
	if err != nil {
		t.Fatalf("acquire from Advertises: %v", err)
	}
	solicit := <-conn.written
	request := <-conn.written
	if solicit.MessageType != dhcpv6.MessageTypeSolicit || request.MessageType != dhcpv6.MessageTypeRequest {
		t.Fatalf("outbound DHCPv6 messages = %s, %s; want SOLICIT then REQUEST", solicit.MessageType, request.MessageType)
	}
	wantServer := acceptanceV6DUID(3)
	if !sameDUID(request.Options.ServerID(), wantServer) {
		t.Fatalf("REQUEST server DUID = %v, want higher-preference server %v", request.Options.ServerID(), wantServer)
	}
	if got, ok := netip.AddrFromSlice(request.Options.OneIANA().Options.OneAddress().IPv6Addr); !ok || got != netip.MustParseAddr("2001:db8::20") {
		t.Errorf("REQUEST IAADDR = %v, want high-preference offer address 2001:db8::20", got)
	}
	if !sameDUID(result.Options.ServerID(), wantServer) {
		t.Errorf("Reply server DUID = %v, want selected Advertise server %v", result.Options.ServerID(), wantServer)
	}
}
