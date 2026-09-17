package dhcp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func mustV4BindingPacket(t *testing.T, typ dhcpv4.MessageType, sid net.IP, hw net.HardwareAddr) *dhcpv4.DHCPv4 {
	t.Helper()
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(typ),
		dhcpv4.WithHwAddr(hw),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(sid)),
	}
	if typ == dhcpv4.MessageTypeAck {
		mods = append(mods,
			dhcpv4.WithYourIP(net.ParseIP("192.0.2.50")),
			dhcpv4.WithNetmask(net.IPMask{255, 255, 255, 0}),
		)
	}
	p, err := dhcpv4.New(mods...)
	if err != nil {
		t.Fatalf("build DHCPv4 packet: %v", err)
	}
	return p
}

func TestV4RenewMatcherBindsServerAndInterface9944(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	grant := net.ParseIP("192.0.2.1")
	other := net.ParseIP("198.51.100.1")
	prev := &Lease{Interface: "wan0", serverID: netip.MustParseAddr("192.0.2.1")}
	req := mustV4BindingPacket(t, dhcpv4.MessageTypeRequest, nil, hw)
	req.TransactionID = dhcpv4.TransactionID{1, 2, 3, 4}
	ack := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, grant, hw)
	ack.TransactionID = req.TransactionID
	spoofACK := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, other, hw)
	spoofACK.TransactionID = req.TransactionID
	wrongXID := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, grant, hw)
	wrongXID.TransactionID = dhcpv4.TransactionID{4, 3, 2, 1}
	wrongClient := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, grant, net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	wrongClient.TransactionID = req.TransactionID
	grantNAK := mustV4BindingPacket(t, dhcpv4.MessageTypeNak, grant, hw)
	grantNAK.TransactionID = req.TransactionID
	spoofNAK := mustV4BindingPacket(t, dhcpv4.MessageTypeNak, other, hw)
	spoofNAK.TransactionID = req.TransactionID

	counterManager := &Manager{}
	matcher := v4RenewMatcher(counterManager, req, prev, false)
	for name, packet := range map[string]*dhcpv4.DHCPv4{
		"granting ACK": ack,
		"granting NAK": grantNAK,
	} {
		if !matcher(packet) {
			t.Errorf("%s rejected; legitimate renewal response must be accepted", name)
		}
	}
	for name, packet := range map[string]*dhcpv4.DHCPv4{
		"spoofed ACK":      spoofACK,
		"wrong-xid ACK":    wrongXID,
		"wrong-client ACK": wrongClient,
		"spoofed NAK":      spoofNAK,
	} {
		if matcher(packet) {
			t.Errorf("%s accepted; response must remain ignored", name)
		}
	}
	if got := counterManager.RenewalBindingStats().DHCPv4ServerIdentityRejects; got != 2 {
		t.Errorf("v4 server-identity rejections after RENEWING = %d, want 2", got)
	}

	// REBINDING remains bound to the granting server for both response
	// types; a new server must not replace or revoke the lease.
	rebindMatcher := v4RenewMatcher(counterManager, req, prev, true)
	alternateACK := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, other, hw)
	alternateACK.TransactionID = req.TransactionID
	if rebindMatcher(alternateACK) {
		t.Error("alternate-server REBIND ACK accepted; response must remain ignored")
	}
	if rebindMatcher(spoofNAK) {
		t.Error("alternate-server REBIND NAK accepted; response must remain ignored")
	}
	if !rebindMatcher(grantNAK) {
		t.Error("granting-server REBIND NAK rejected")
	}
	if got := counterManager.RenewalBindingStats().DHCPv4ServerIdentityRejects; got != 4 {
		t.Errorf("v4 server-identity rejections after REBINDING = %d, want 4", got)
	}
}

func TestRenewLeaseInterfaceBinding9944(t *testing.T) {
	v4 := &Lease{Interface: "wan0"}
	v6 := &Lease{Interface: "wan0"}
	for name, lease := range map[string]*Lease{"v4": v4, "v6": v6} {
		t.Run(name, func(t *testing.T) {
			if !leaseInterfaceMatches("wan0", lease) {
				t.Fatal("lease rejected on its owning interface")
			}
			if leaseInterfaceMatches("wan1", lease) {
				t.Fatal("lease from another interface accepted")
			}
		})
	}
}

func TestRenewExchangeRejectsLeaseFromOtherInterface9944(t *testing.T) {
	prevV4 := &Lease{
		Interface: "wan0",
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
	}
	prevV6 := &Lease{
		Interface: "wan0",
		Address:   netip.MustParsePrefix("2001:db8::50/128"),
	}
	for name, exchange := range map[string]func() error{
		"v4": func() error {
			_, err := (&Manager{}).doDHCPv4(context.Background(), "wan1", exchangeRenew, prevV4)
			return err
		},
		"v6": func() error {
			_, err := (&Manager{}).doDHCPv6(context.Background(), "wan1", exchangeRenew, prevV6, nil)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := exchange()
			if err == nil || !strings.Contains(err.Error(), "lease belongs to interface") {
				t.Fatalf("cross-interface renewal error = %v, want interface-binding rejection", err)
			}
		})
	}
}

func mustV6BindingMessage(t *testing.T, typ dhcpv6.MessageType, clientID, serverID dhcpv6.DUID) *dhcpv6.Message {
	t.Helper()
	mods := []dhcpv6.Modifier{}
	if clientID != nil {
		mods = append(mods, dhcpv6.WithClientID(clientID))
	}
	if serverID != nil {
		mods = append(mods, dhcpv6.WithServerID(serverID))
	}
	msg, err := dhcpv6.NewMessage(mods...)
	if err != nil {
		t.Fatalf("build DHCPv6 message: %v", err)
	}
	msg.MessageType = typ
	return msg
}

func TestV6RenewMatcherBindsDUIDAndInterface9944(t *testing.T) {
	clientDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	grantDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}}
	otherDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 3}}
	prev := &Lease{Interface: "wan0", v6ServerDUID: grantDUID}
	req := mustV6BindingMessage(t, dhcpv6.MessageTypeRenew, clientDUID, grantDUID)
	req.TransactionID = dhcpv6.TransactionID{1, 2, 3}
	reply := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, grantDUID)
	reply.TransactionID = req.TransactionID
	spoofReply := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, otherDUID)
	spoofReply.TransactionID = req.TransactionID
	wrongClient := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, otherDUID, grantDUID)
	wrongClient.TransactionID = req.TransactionID
	wrongXID := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, grantDUID)
	wrongXID.TransactionID = dhcpv6.TransactionID{3, 2, 1}
	missingServer := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, nil)
	missingServer.TransactionID = req.TransactionID

	counterManager := &Manager{}
	matcher := v6RenewMatcher(counterManager, req, prev, false)
	if !matcher(reply) {
		t.Error("granting-server Reply rejected; legitimate RENEW must work")
	}
	for name, packet := range map[string]*dhcpv6.Message{
		"wrong-DUID Reply":        spoofReply,
		"wrong-client Reply":      wrongClient,
		"wrong-transaction Reply": wrongXID,
		"missing-server Reply":    missingServer,
	} {
		if matcher(packet) {
			t.Errorf("%s accepted; response must remain ignored", name)
		}
	}
	if got := counterManager.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 2 {
		t.Errorf("v6 server-identity rejections after RENEWING = %d, want 2", got)
	}

	// REBINDING remains bound to the original granting server: an alternate
	// Reply cannot replace the lease's renewal binding.
	rebindMatcher := v6RenewMatcher(counterManager, req, prev, true)
	alternateReply := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, otherDUID)
	alternateReply.TransactionID = req.TransactionID
	if rebindMatcher(alternateReply) {
		t.Error("alternate-server REBIND Reply accepted; response must remain ignored")
	}
	if rebindMatcher(missingServer) {
		t.Error("Reply without server DUID accepted")
	}
	if got := counterManager.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 4 {
		t.Errorf("v6 server-identity rejections after REBINDING = %d, want 4", got)
	}

	before := &Lease{
		Address: netip.MustParsePrefix("2001:db8::1/128"), LeaseTime: time.Hour,
		v6ServerDUID: grantDUID,
	}
	after := *before
	after.v6ServerDUID = otherDUID
	if !leaseContentChanged(before, &after) {
		t.Error("server DUID transition hidden from leaseContentChanged")
	}
}
