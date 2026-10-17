package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func TestRebindAcceptsAnyServer14600(t *testing.T) {
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	partner := net.ParseIP("198.51.100.1")
	prev := &Lease{Interface: "wan0", serverID: netip.MustParseAddr("192.0.2.1")}
	req := mustV4BindingPacket(t, dhcpv4.MessageTypeRequest, nil, hw)
	req.TransactionID = dhcpv4.TransactionID{1, 2, 3, 4}

	partnerACK := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, partner, hw)
	partnerACK.TransactionID = req.TransactionID
	partnerNAK := mustV4BindingPacket(t, dhcpv4.MessageTypeNak, partner, hw)
	partnerNAK.TransactionID = req.TransactionID
	wrongXID := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, partner, hw)
	wrongXID.TransactionID = dhcpv4.TransactionID{4, 3, 2, 1}
	wrongClient := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, partner, net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	wrongClient.TransactionID = req.TransactionID
	missingServer := mustV4BindingPacket(t, dhcpv4.MessageTypeAck, nil, hw)
	missingServer.TransactionID = req.TransactionID

	mgr := &Manager{}
	rebind := v4RenewMatcher(mgr, req, prev, true)
	if !rebind(partnerACK) {
		t.Error("v4 REBIND partner ACK rejected; any server must be able to rebind (RFC 2131 4.3.2)")
	}
	if !rebind(partnerNAK) {
		t.Error("v4 REBIND partner NAK rejected; any server must be able to rebind")
	}
	// Controls: xid/chaddr and presence of a (valid) server-id still enforced in rebind.
	for name, pkt := range map[string]*dhcpv4.DHCPv4{
		"wrong-xid": wrongXID, "wrong-client": wrongClient, "missing-server": missingServer,
	} {
		if rebind(pkt) {
			t.Errorf("v4 REBIND %s accepted; identity checks must still apply", name)
		}
	}
	// Only missing-server is a server-identity reject; xid/chaddr drop earlier.
	if got := mgr.RenewalBindingStats().DHCPv4ServerIdentityRejects; got != 1 {
		t.Errorf("v4 rebind server-identity rejects = %d, want 1 (missing server only)", got)
	}
	// Renew (rebind=false) still bound to granting server.
	renew := v4RenewMatcher(mgr, req, prev, false)
	if renew(partnerACK) {
		t.Error("v4 RENEW partner ACK accepted; RENEWING must stay bound to granting server")
	}
	if got := mgr.RenewalBindingStats().DHCPv4ServerIdentityRejects; got != 2 {
		t.Errorf("v4 rejects after renew partner = %d, want 2", got)
	}
	// Accepted partner ACK stores partner as new server-id.
	lease, err := leaseFromACKv4("wan0", partnerACK)
	if err != nil {
		t.Fatalf("leaseFromACKv4(partner ACK): %v", err)
	}
	if lease.serverID != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("stored serverID = %v, want partner 198.51.100.1", lease.serverID)
	}

	// v6
	clientDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	grantDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}}
	partnerDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 3}}
	prev6 := &Lease{Interface: "wan0", v6ServerDUID: grantDUID}
	req6 := mustV6BindingMessage(t, dhcpv6.MessageTypeRebind, clientDUID, nil)
	req6.TransactionID = dhcpv6.TransactionID{1, 2, 3}
	partnerReply := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, partnerDUID)
	partnerReply.TransactionID = req6.TransactionID
	wrongClient6 := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, partnerDUID, partnerDUID)
	wrongClient6.TransactionID = req6.TransactionID
	wrongXID6 := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, partnerDUID)
	wrongXID6.TransactionID = dhcpv6.TransactionID{3, 2, 1}
	missing6 := mustV6BindingMessage(t, dhcpv6.MessageTypeReply, clientDUID, nil)
	missing6.TransactionID = req6.TransactionID

	mgr6 := &Manager{}
	rebind6 := v6RenewMatcher(mgr6, req6, prev6, true)
	if !rebind6(partnerReply) {
		t.Error("v6 REBIND partner Reply rejected; any server must be able to rebind (RFC 8415 18.2.5)")
	}
	for name, pkt := range map[string]*dhcpv6.Message{
		"wrong-client": wrongClient6, "wrong-xid": wrongXID6, "missing-server": missing6,
	} {
		if rebind6(pkt) {
			t.Errorf("v6 REBIND %s accepted; identity checks must still apply", name)
		}
	}
	if got := mgr6.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 1 {
		t.Errorf("v6 rebind server-identity rejects = %d, want 1 (missing server only)", got)
	}
	renew6 := v6RenewMatcher(mgr6, req6, prev6, false)
	if renew6(partnerReply) {
		t.Error("v6 RENEW partner Reply accepted; RENEW must stay bound to granting server")
	}
	if got := mgr6.RenewalBindingStats().DHCPv6ServerIdentityRejects; got != 2 {
		t.Errorf("v6 rejects after renew partner = %d, want 2", got)
	}
	// Partner Reply stores partner DUID on parsed lease.
	iana := &dhcpv6.OptIANA{IaId: v6IANAIAID(hw)}
	iana.Options.Add(acceptanceV6Address("2606:4700::50"))
	replyWithIA, err := dhcpv6.NewMessage(dhcpv6.WithClientID(clientDUID), dhcpv6.WithServerID(partnerDUID))
	if err != nil {
		t.Fatalf("build partner Reply: %v", err)
	}
	replyWithIA.MessageType = dhcpv6.MessageTypeReply
	replyWithIA.AddOption(iana)
	wantIAID := v6IANAIAID(hw)
	res, err := (&Manager{}).parseV6ReplyChecked(t.Context(), "wan0", replyWithIA, nil, &wantIAID, nil)
	if err != nil {
		t.Fatalf("parse partner Reply: %v", err)
	}
	if !sameDUID(res.lease.v6ServerDUID, partnerDUID) {
		t.Errorf("stored v6ServerDUID = %v, want partner DUID", res.lease.v6ServerDUID)
	}
}
